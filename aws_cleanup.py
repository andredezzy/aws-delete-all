#!/usr/bin/env python3
"""
AWS Cleanup Script (DRY-RUN by default)

Per-region cleanup:
- EC2: instances, available EBS volumes, AMIs (+ snapshots), loose snapshots, Elastic IPs, key pairs
- Lambda: functions
- S3: empties versioned/unversioned buckets then deletes them (bucket-region aware)
- ECR: repositories (force delete images)
- CloudWatch Logs: log groups
- ENI: deletes 'available' network interfaces
- Security Groups: revokes rules, removes cross-references, deletes non-default SGs
- Load Balancers: ALB/NLB (ELBv2) + Classic ELB, target groups
- VPC teardown (best-effort, order-aware): endpoints, ELBs, NAT GWs, IGWs (detach), subnets, non-main route tables, non-default NACLs, peering, VPN attachments/GWs, then VPC
- RDS: DB clusters & instances (removes deletion protection), snapshots, subnet groups
- EKS: add-ons, fargate profiles, nodegroups, clusters; tries to remove IAM OIDC provider

Global (opt-in):
- Route 53: disable DNSSEC (if enabled), delete ALL record sets except apex NS/SOA, disassociate VPCs (private zones), then delete hosted zones
- IAM: deletes identity providers (OIDC/SAML, excludes those with "aws" or "DO_NOT_DELETE" in name), deletes roles (excludes those starting with "AWS"), detaches and deletes customer-managed policies

Usage examples:
  python aws_cleanup.py
  python aws_cleanup.py --regions us-east-1 us-west-2
  python aws_cleanup.py --really-delete
  python aws_cleanup.py --include-route53
  python aws_cleanup.py --include-iam
  python aws_cleanup.py --really-delete --include-route53 --include-iam
  # control RDS final snapshots (default: skip)
  python aws_cleanup.py --really-delete --rds-final-snapshot-prefix final-$(date +%s)

Tips:
  export AWS_PAGER=""
  export AWS_PROFILE=your-profile
"""

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, WaiterError

CFG = Config(retries={"max_attempts": 10, "mode": "standard"})
MAX_WORKERS = 16

# ---------------- Utilities ----------------
def regions():
    ec2 = boto3.client("ec2", config=CFG)
    return [r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"]]

def confirm_account():
    sts = boto3.client("sts", config=CFG)
    return sts.get_caller_identity()["Account"]

def safe_call(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except ClientError as e:
        print(f"  ! {e}", file=sys.stderr)
        return None

def action_line(actually: bool, verb: str, resource: str) -> str:
    return ("" if actually else "[DRY-RUN] ") + f"{verb}: {resource}"

# ---------------- EC2 core ----------------
def cleanup_ec2(region: str, actually: bool):
    ec2 = boto3.client("ec2", region_name=region, config=CFG)

    # instances
    resp = ec2.describe_instances(Filters=[{"Name":"instance-state-name","Values":["pending","running","stopping","stopped"]}])
    ids = [i["InstanceId"] for r in resp["Reservations"] for i in r["Instances"]]
    if ids:
        print(action_line(actually, "Terminate EC2 instances", f"{region} {ids}"))
        if actually:
            safe_call(ec2.terminate_instances, InstanceIds=ids)

    # available EBS volumes
    vols = ec2.describe_volumes(Filters=[{"Name":"status","Values":["available"]}])["Volumes"]
    for v in vols:
        print(action_line(actually, "Delete EBS volume", f"{region} {v['VolumeId']}"))
        if actually:
            safe_call(ec2.delete_volume, VolumeId=v["VolumeId"])

    # AMIs + their snapshots
    imgs = ec2.describe_images(Owners=["self"])["Images"]
    for img in imgs:
        snap_ids = [
            bdm.get("Ebs", {}).get("SnapshotId")
            for bdm in img.get("BlockDeviceMappings", [])
            if bdm.get("Ebs")
        ]
        print(action_line(actually, "Deregister AMI", f"{region} {img['ImageId']} ({img.get('Name','')})"))
        if actually:
            safe_call(ec2.deregister_image, ImageId=img["ImageId"])
        for sid in filter(None, snap_ids):
            print(action_line(actually, "Delete snapshot", f"{region} {sid}"))
            if actually:
                safe_call(ec2.delete_snapshot, SnapshotId=sid)

    # loose snapshots
    snaps = ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"]
    for s in snaps:
        print(action_line(actually, "Delete snapshot", f"{region} {s['SnapshotId']}"))
        if actually:
            safe_call(ec2.delete_snapshot, SnapshotId=s["SnapshotId"])

    # Elastic IPs
    addrs = ec2.describe_addresses()["Addresses"]
    for a in addrs:
        alloc = a.get("AllocationId")
        if alloc:
            print(action_line(actually, "Release Elastic IP", f"{region} {alloc}"))
            if actually:
                safe_call(ec2.release_address, AllocationId=alloc)

    # key pairs
    kps = ec2.describe_key_pairs()["KeyPairs"]
    for kp in kps:
        print(action_line(actually, "Delete key pair", f"{region} {kp['KeyName']}"))
        if actually:
            safe_call(ec2.delete_key_pair, KeyName=kp["KeyName"])

# ---------------- ENIs ----------------
def cleanup_enis(region: str, actually: bool):
    ec2 = boto3.client("ec2", region_name=region, config=CFG)
    enis = ec2.describe_network_interfaces(Filters=[{"Name":"status","Values":["available"]}])["NetworkInterfaces"]
    for eni in enis:
        eni_id = eni["NetworkInterfaceId"]
        print(action_line(actually, "Delete ENI", f"{region} {eni_id}"))
        if actually:
            safe_call(ec2.delete_network_interface, NetworkInterfaceId=eni_id)

# ---------------- Security Groups ----------------
def _revoke_all_rules_on_group(ec2, sg, actually: bool):
    gid = sg["GroupId"]
    if sg.get("IpPermissions"):
        print(action_line(actually, "Revoke SG ingress", f"{gid} ({len(sg['IpPermissions'])} rules)"))
        if actually:
            safe_call(ec2.revoke_security_group_ingress, GroupId=gid, IpPermissions=sg["IpPermissions"])
    if sg.get("IpPermissionsEgress"):
        print(action_line(actually, "Revoke SG egress", f"{gid} ({len(sg['IpPermissionsEgress'])} rules)"))
        if actually:
            safe_call(ec2.revoke_security_group_egress, GroupId=gid, IpPermissions=sg["IpPermissionsEgress"])

def _remove_other_groups_referencing(ec2, target_group_id: str, actually: bool):
    sgs = ec2.describe_security_groups()["SecurityGroups"]
    for sg in sgs:
        gid = sg["GroupId"]
        in_perms, out_perms = [], []
        for p in sg.get("IpPermissions", []):
            pairs = [pair for pair in p.get("UserIdGroupPairs", []) if pair.get("GroupId")==target_group_id]
            if pairs:
                in_perms.append({"IpProtocol":p["IpProtocol"],"FromPort":p.get("FromPort"),"ToPort":p.get("ToPort"),"UserIdGroupPairs":pairs})
        if in_perms:
            print(action_line(actually, "Revoke referencing ingress", f"{gid} -> {target_group_id} ({len(in_perms)})"))
            if actually:
                safe_call(ec2.revoke_security_group_ingress, GroupId=gid, IpPermissions=in_perms)
        for p in sg.get("IpPermissionsEgress", []):
            pairs = [pair for pair in p.get("UserIdGroupPairs", []) if pair.get("GroupId")==target_group_id]
            if pairs:
                out_perms.append({"IpProtocol":p["IpProtocol"],"FromPort":p.get("FromPort"),"ToPort":p.get("ToPort"),"UserIdGroupPairs":pairs})
        if out_perms:
            print(action_line(actually, "Revoke referencing egress", f"{gid} -> {target_group_id} ({len(out_perms)})"))
            if actually:
                safe_call(ec2.revoke_security_group_egress, GroupId=gid, IpPermissions=out_perms)

def cleanup_security_groups(region: str, actually: bool):
    ec2 = boto3.client("ec2", region_name=region, config=CFG)
    sgs = ec2.describe_security_groups()["SecurityGroups"]
    for sg in [sg for sg in sgs if sg.get("GroupName")!="default"]:
        gid = sg["GroupId"]
        # skip if any ENI still uses it
        enis = ec2.describe_network_interfaces(Filters=[{"Name":"group-id","Values":[gid]}])["NetworkInterfaces"]
        if enis:
            print(action_line(False, "Skip SG in use (ENIs attached)", f"{region} {gid}"))
            continue
        _revoke_all_rules_on_group(ec2, sg, actually)
        _remove_other_groups_referencing(ec2, gid, actually)
        print(action_line(actually, "Delete Security Group", f"{region} {gid}"))
        if actually:
            if not safe_call(ec2.delete_security_group, GroupId=gid):
                _remove_other_groups_referencing(ec2, gid, actually)
                safe_call(ec2.delete_security_group, GroupId=gid)

# ---------------- S3 ----------------
def empty_bucket_versions(s3_client, bucket: str):
    paginator = s3_client.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = []
        for ver in page.get("Versions", []):
            objs.append({"Key":ver["Key"],"VersionId":ver["VersionId"]})
        for dm in page.get("DeleteMarkers", []):
            objs.append({"Key":dm["Key"],"VersionId":dm["VersionId"]})
        while objs:
            batch, objs = objs[:1000], objs[1000:]
            s3_client.delete_objects(Bucket=bucket, Delete={"Objects":batch})

def empty_bucket_unversioned(s3_client, bucket: str):
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key":o["Key"]} for o in page.get("Contents", [])]
        while objs:
            batch, objs = objs[:1000], objs[1000:]
            s3_client.delete_objects(Bucket=bucket, Delete={"Objects":batch})

def cleanup_s3(region: str, actually: bool):
    s3_global = boto3.client("s3", config=CFG)
    s3_regional = boto3.client("s3", region_name=region, config=CFG)
    for b in s3_global.list_buckets().get("Buckets", []):
        name = b["Name"]
        try:
            loc = s3_regional.get_bucket_location(Bucket=name)["LocationConstraint"] or "us-east-1"
        except ClientError:
            continue
        if loc != region:
            continue
        print(action_line(actually, "Empty + delete S3 bucket", f"{region} s3://{name}"))
        if not actually:
            continue
        try: empty_bucket_versions(s3_regional, name)
        except ClientError: pass
        try: empty_bucket_unversioned(s3_regional, name)
        except ClientError: pass
        safe_call(s3_regional.delete_bucket, Bucket=name)

# ---------------- ECR ----------------
def cleanup_ecr(region: str, actually: bool):
    ecr = boto3.client("ecr", region_name=region, config=CFG)
    try:
        repos = ecr.describe_repositories().get("repositories", [])
    except ClientError:
        repos = []
    for r in repos:
        rname = r["repositoryName"]
        print(action_line(actually, "Delete ECR repository (force)", f"{region} {rname}"))
        if actually:
            safe_call(ecr.delete_repository, repositoryName=rname, force=True)

# ---------------- Lambda ----------------
def cleanup_lambda(region: str, actually: bool):
    lam = boto3.client("lambda", region_name=region, config=CFG)
    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page.get("Functions", []):
            fname = fn["FunctionName"]
            print(action_line(actually, "Delete Lambda function", f"{region} {fname}"))
            if actually:
                safe_call(lam.delete_function, FunctionName=fname)

# ---------------- CloudWatch Logs ----------------
def cleanup_logs(region: str, actually: bool):
    logs = boto3.client("logs", region_name=region, config=CFG)
    paginator = logs.get_paginator("describe_log_groups")
    for page in paginator.paginate():
        for lg in page.get("logGroups", []):
            name = lg["logGroupName"]
            print(action_line(actually, "Delete Log Group", f"{region} {name}"))
            if actually:
                safe_call(logs.delete_log_group, logGroupName=name)

# ---------------- Load Balancers ----------------
def cleanup_elbv2(region: str, actually: bool):
    elb = boto3.client("elbv2", region_name=region, config=CFG)
    # delete LBs first (listeners go with them)
    try:
        lbs = []
        paginator = elb.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            lbs.extend(page.get("LoadBalancers", []))
        for lb in lbs:
            arn = lb["LoadBalancerArn"]
            print(action_line(actually, "Delete ELBv2", f"{region} {arn}"))
            if actually:
                safe_call(elb.delete_load_balancer, LoadBalancerArn=arn)
        # then delete target groups
        tgs = []
        paginator = elb.get_paginator("describe_target_groups")
        for page in paginator.paginate():
            tgs.extend(page.get("TargetGroups", []))
        for tg in tgs:
            t_arn = tg["TargetGroupArn"]
            print(action_line(actually, "Delete Target Group", f"{region} {t_arn}"))
            if actually:
                safe_call(elb.delete_target_group, TargetGroupArn=t_arn)
    except ClientError:
        pass

def cleanup_elb_classic(region: str, actually: bool):
    elb = boto3.client("elb", region_name=region, config=CFG)
    try:
        names = [lb["LoadBalancerName"] for lb in elb.describe_load_balancers()["LoadBalancerDescriptions"]]
        for name in names:
            print(action_line(actually, "Delete Classic ELB", f"{region} {name}"))
            if actually:
                safe_call(elb.delete_load_balancer, LoadBalancerName=name)
    except ClientError:
        pass

# ---------------- VPC teardown ----------------
def cleanup_vpcs(region: str, actually: bool):
    ec2 = boto3.client("ec2", region_name=region, config=CFG)
    vpcs = ec2.describe_vpcs()["Vpcs"]
    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        print(action_line(actually, "VPC teardown (best-effort)", f"{region} {vpc_id}"))

        # Endpoints (interface & gateway)
        try:
            eps = ec2.describe_vpc_endpoints(Filters=[{"Name":"vpc-id","Values":[vpc_id]}])["VpcEndpoints"]
            for ep in eps:
                print(action_line(actually, "Delete VPC Endpoint", f"{region} {ep['VpcEndpointId']}"))
                if actually:
                    safe_call(ec2.delete_vpc_endpoints, VpcEndpointIds=[ep["VpcEndpointId"]])
        except ClientError: pass

        # NAT Gateways
        try:
            ngw = ec2.describe_nat_gateways(Filter=[{"Name":"vpc-id","Values":[vpc_id]}])["NatGateways"]
            for n in ngw:
                print(action_line(actually, "Delete NAT Gateway", f"{region} {n['NatGatewayId']}"))
                if actually:
                    safe_call(ec2.delete_nat_gateway, NatGatewayId=n["NatGatewayId"])
        except ClientError: pass

        # Internet Gateways (detach then delete)
        try:
            igws = ec2.describe_internet_gateways(Filters=[{"Name":"attachment.vpc-id","Values":[vpc_id]}])["InternetGateways"]
            for igw in igws:
                igw_id = igw["InternetGatewayId"]
                print(action_line(actually, "Detach IGW", f"{region} {igw_id} from {vpc_id}"))
                if actually:
                    safe_call(ec2.detach_internet_gateway, InternetGatewayId=igw_id, VpcId=vpc_id)
                print(action_line(actually, "Delete IGW", f"{region} {igw_id}"))
                if actually:
                    safe_call(ec2.delete_internet_gateway, InternetGatewayId=igw_id)
        except ClientError: pass

        # Peering connections (if requester or accepter is this VPC)
        try:
            peers = ec2.describe_vpc_peering_connections()["VpcPeeringConnections"]
            for pcx in peers:
                if any([
                    pcx.get("RequesterVpcInfo",{}).get("VpcId")==vpc_id,
                    pcx.get("AccepterVpcInfo",{}).get("VpcId")==vpc_id
                ]):
                    print(action_line(actually, "Delete VPC Peering", f"{region} {pcx['VpcPeeringConnectionId']}"))
                    if actually:
                        safe_call(ec2.delete_vpc_peering_connection, VpcPeeringConnectionId=pcx["VpcPeeringConnectionId"])
        except ClientError: pass

        # VPN attachments / gateways (best-effort)
        try:
            vgws = ec2.describe_vpn_gateways(Filters=[{"Name":"attachment.vpc-id","Values":[vpc_id]}])["VpnGateways"]
            for vgw in vgws:
                print(action_line(actually, "Detach VPN Gateway", f"{region} {vgw['VpnGatewayId']} from {vpc_id}"))
                if actually:
                    safe_call(ec2.detach_vpn_gateway, VpnGatewayId=vgw["VpnGatewayId"], VpcId=vpc_id)
                print(action_line(actually, "Delete VPN Gateway", f"{region} {vgw['VpnGatewayId']}"))
                if actually:
                    safe_call(ec2.delete_vpn_gateway, VpnGatewayId=vgw["VpnGatewayId"])
        except ClientError: pass

        # Subnets (must be empty; ELBs/endpoints/ENIs handled earlier)
        try:
            subnets = ec2.describe_subnets(Filters=[{"Name":"vpc-id","Values":[vpc_id]}])["Subnets"]
            for s in subnets:
                print(action_line(actually, "Delete Subnet", f"{region} {s['SubnetId']}"))
                if actually:
                    safe_call(ec2.delete_subnet, SubnetId=s["SubnetId"])
        except ClientError: pass

        # Non-main Route Tables
        try:
            rts = ec2.describe_route_tables(Filters=[{"Name":"vpc-id","Values":[vpc_id]}])["RouteTables"]
            for rt in rts:
                is_main = False
                for assoc in rt.get("Associations", []):
                    if assoc.get("Main"):
                        is_main = True
                    # disassociate non-main associations
                    assoc_id = assoc.get("RouteTableAssociationId")
                    if assoc_id and not assoc.get("Main"):
                        print(action_line(actually, "Disassociate Route Table", f"{region} {assoc_id}"))
                        if actually:
                            safe_call(ec2.disassociate_route_table, AssociationId=assoc_id)
                if not is_main:
                    print(action_line(actually, "Delete Route Table", f"{region} {rt['RouteTableId']}"))
                    if actually:
                        safe_call(ec2.delete_route_table, RouteTableId=rt["RouteTableId"])
        except ClientError: pass

        # Non-default NACLs
        try:
            nacls = ec2.describe_network_acls(Filters=[{"Name":"vpc-id","Values":[vpc_id]}])["NetworkAcls"]
            for acl in nacls:
                if not acl.get("IsDefault"):
                    print(action_line(actually, "Delete Network ACL", f"{region} {acl['NetworkAclId']}"))
                    if actually:
                        safe_call(ec2.delete_network_acl, NetworkAclId=acl["NetworkAclId"])
        except ClientError: pass

        # Finally, delete VPC
        print(action_line(actually, "Delete VPC", f"{region} {vpc_id}"))
        if actually:
            safe_call(ec2.delete_vpc, VpcId=vpc_id)

# ---------------- RDS ----------------
def cleanup_rds(region: str, actually: bool, final_snapshot_prefix: str|None):
    rds = boto3.client("rds", region_name=region, config=CFG)
    deleted_resources = False  # Track if we actually deleted any RDS resources

    # Clusters (Aurora)
    try:
        clusters = rds.describe_db_clusters()["DBClusters"]
    except ClientError:
        clusters = []
    for c in clusters:
        cid = c["DBClusterIdentifier"]
        print(action_line(actually, "RDS Cluster: disable deletion protection", f"{region} {cid}"))
        if actually:
            safe_call(rds.modify_db_cluster, DBClusterIdentifier=cid, DeletionProtection=False, ApplyImmediately=True)
        # deleting cluster deletes its instances
        kwargs = {"DBClusterIdentifier": cid, "SkipFinalSnapshot": True}
        if final_snapshot_prefix:
            kwargs = {"DBClusterIdentifier": cid,
                      "FinalDBSnapshotIdentifier": f"{final_snapshot_prefix}-{cid}"[:255],
                      "SkipFinalSnapshot": False}
        print(action_line(actually, "Delete RDS Cluster", f"{region} {cid}"))
        if actually:
            result = safe_call(rds.delete_db_cluster, **kwargs)
            if result:  # Only set if deletion was successful
                deleted_resources = True

    # Instances not in clusters
    try:
        instances = rds.describe_db_instances()["DBInstances"]
    except ClientError:
        instances = []
    for i in instances:
        if i.get("DBClusterIdentifier"):  # cluster-managed; skip
            continue
        iid = i["DBInstanceIdentifier"]
        print(action_line(actually, "RDS Instance: disable deletion protection", f"{region} {iid}"))
        if actually:
            safe_call(rds.modify_db_instance, DBInstanceIdentifier=iid, DeletionProtection=False, ApplyImmediately=True)
        kwargs = {"DBInstanceIdentifier": iid, "SkipFinalSnapshot": True, "DeleteAutomatedBackups": True}
        if final_snapshot_prefix:
            kwargs = {"DBInstanceIdentifier": iid,
                      "FinalDBSnapshotIdentifier": f"{final_snapshot_prefix}-{iid}"[:255],
                      "DeleteAutomatedBackups": True,
                      "SkipFinalSnapshot": False}
        print(action_line(actually, "Delete RDS Instance", f"{region} {iid}"))
        if actually:
            result = safe_call(rds.delete_db_instance, **kwargs)
            if result:  # Only set if deletion was successful
                deleted_resources = True

    # Snapshots (manual + cluster)
    try:
        snaps = rds.describe_db_snapshots(SnapshotType="manual")["DBSnapshots"]
    except ClientError:
        snaps = []
    for s in snaps:
        sid = s["DBSnapshotIdentifier"]
        print(action_line(actually, "Delete RDS Snapshot", f"{region} {sid}"))
        if actually:
            safe_call(rds.delete_db_snapshot, DBSnapshotIdentifier=sid)

    try:
        csnaps = rds.describe_db_cluster_snapshots(SnapshotType="manual")["DBClusterSnapshots"]
    except ClientError:
        csnaps = []
    for s in csnaps:
        sid = s["DBClusterSnapshotIdentifier"]
        print(action_line(actually, "Delete RDS Cluster Snapshot", f"{region} {sid}"))
        if actually:
            safe_call(rds.delete_db_cluster_snapshot, DBClusterSnapshotIdentifier=sid)

    # Wait for DB instances/clusters to be fully deleted before deleting subnet groups
    # Only wait if we actually deleted RDS resources
    if actually and deleted_resources:
        print(f"  Waiting for RDS resources to be fully deleted in {region}...")
        time.sleep(30)  # Give some time for deletions to propagate
    
    # Subnet groups (best-effort with retry)
    try:
        sgs = rds.describe_db_subnet_groups()["DBSubnetGroups"]
        for sg in sgs:
            name = sg["DBSubnetGroupName"]
            print(action_line(actually, "Delete RDS Subnet Group", f"{region} {name}"))
            if actually:
                # Retry subnet group deletion up to 3 times with delays
                for attempt in range(3):
                    try:
                        rds.delete_db_subnet_group(DBSubnetGroupName=name)
                        break
                    except ClientError as e:
                        if "InvalidDBSubnetGroupStateFault" in str(e) and attempt < 2:
                            print(f"  Subnet group {name} still in use, waiting 30s (attempt {attempt + 1}/3)...")
                            time.sleep(30)
                        else:
                            print(f"  ! Failed to delete subnet group {name}: {e}", file=sys.stderr)
                            break
    except ClientError:
        pass

# ---------------- EKS ----------------
def cleanup_eks(region: str, actually: bool):
    eks = boto3.client("eks", region_name=region, config=CFG)
    iam = boto3.client("iam", config=CFG)

    def try_delete_oidc_provider(issuer_url: str):
        # issuer like "https://oidc.eks.<region>.amazonaws.com/id/XXXXXXXX"
        if not issuer_url:
            return
        suffix = issuer_url.replace("https://", "")
        try:
            providers = iam.list_open_id_connect_providers()["OpenIDConnectProviderList"]
            for p in providers:
                arn = p["Arn"]
                desc = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
                # desc['Url'] has no https://
                if desc.get("Url") == suffix:
                    print(action_line(actually, "Delete IAM OIDC Provider", arn))
                    if actually:
                        safe_call(iam.delete_open_id_connect_provider, OpenIDConnectProviderArn=arn)
        except ClientError:
            pass

    # list clusters
    try:
        clusters = eks.list_clusters().get("clusters", [])
    except ClientError:
        clusters = []
    for c in clusters:
        print(action_line(actually, "EKS Cluster cleanup", f"{region} {c}"))

        # add-ons
        try:
            addons = eks.list_addons(clusterName=c).get("addons", [])
            for a in addons:
                print(action_line(actually, "Delete EKS Add-on", f"{region} {c}/{a}"))
                if actually:
                    safe_call(eks.delete_addon, clusterName=c, addonName=a)
        except ClientError:
            pass

        # fargate profiles
        try:
            fps = eks.list_fargate_profiles(clusterName=c).get("fargateProfileNames", [])
            for fp in fps:
                print(action_line(actually, "Delete EKS Fargate Profile", f"{region} {c}/{fp}"))
                if actually:
                    safe_call(eks.delete_fargate_profile, clusterName=c, fargateProfileName=fp)
        except ClientError:
            pass

        # nodegroups
        try:
            ngs = eks.list_nodegroups(clusterName=c).get("nodegroups", [])
            for ng in ngs:
                print(action_line(actually, "Delete EKS Nodegroup", f"{region} {c}/{ng}"))
                if actually:
                    safe_call(eks.delete_nodegroup, clusterName=c, nodegroupName=ng)
        except ClientError:
            pass

        # delete cluster
        print(action_line(actually, "Delete EKS Cluster", f"{region} {c}"))
        issuer = None
        if actually:
            desc = safe_call(eks.describe_cluster, name=c)
            issuer = (desc or {}).get("cluster", {}).get("identity", {}).get("oidc", {}).get("issuer")
            safe_call(eks.delete_cluster, name=c)
        # attempt to remove IAM OIDC provider
        if issuer:
            try_delete_oidc_provider(issuer)

# ---------------- IAM (global) ----------------
def cleanup_iam(actually: bool):
    iam = boto3.client("iam", config=CFG)
    
    # Delete identity providers (OIDC and SAML) with filtering
    try:
        # OIDC providers
        oidc_providers = iam.list_open_id_connect_providers().get("OpenIDConnectProviderList", [])
        for provider in oidc_providers:
            arn = provider["Arn"]
            # Extract provider name from ARN (last part after /)
            provider_name = arn.split("/")[-1] if "/" in arn else arn
            provider_name_lower = provider_name.lower()
            
            # Skip if contains "aws" or "do_not_delete" (case insensitive)
            if "aws" in provider_name_lower or "do_not_delete" in provider_name_lower:
                print(action_line(False, "Skip OIDC Provider (protected)", f"{provider_name} ({arn})"))
                continue
            
            print(action_line(actually, "Delete OIDC Identity Provider", f"{provider_name} ({arn})"))
            if actually:
                safe_call(iam.delete_open_id_connect_provider, OpenIDConnectProviderArn=arn)
    except ClientError:
        pass
    
    try:
        # SAML providers
        saml_providers = iam.list_saml_providers().get("SAMLProviderList", [])
        for provider in saml_providers:
            arn = provider["Arn"]
            # Extract provider name from ARN (last part after /)
            provider_name = arn.split("/")[-1] if "/" in arn else arn
            provider_name_lower = provider_name.lower()
            
            # Skip if contains "aws" or "do_not_delete" (case insensitive)
            if "aws" in provider_name_lower or "do_not_delete" in provider_name_lower:
                print(action_line(False, "Skip SAML Provider (protected)", f"{provider_name} ({arn})"))
                continue
            
            print(action_line(actually, "Delete SAML Identity Provider", f"{provider_name} ({arn})"))
            if actually:
                safe_call(iam.delete_saml_provider, SAMLProviderArn=arn)
    except ClientError:
        pass
    
    # Delete IAM roles (exclude AWS service roles)
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                
                # Skip if starts with "AWS" (case sensitive)
                if role_name.startswith("AWS"):
                    print(action_line(False, "Skip IAM Role (AWS service role)", f"{role_name}"))
                    continue
                
                print(action_line(actually, "IAM Role cleanup", f"{role_name}"))
                
                # Detach managed policies
                try:
                    attached_policies = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                    for policy in attached_policies:
                        policy_arn = policy["PolicyArn"]
                        print(action_line(actually, "Detach managed policy from role", f"{policy['PolicyName']} from {role_name}"))
                        if actually:
                            safe_call(iam.detach_role_policy, RoleName=role_name, PolicyArn=policy_arn)
                except ClientError:
                    pass
                
                # Delete inline policies
                try:
                    inline_policies = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
                    for policy_name in inline_policies:
                        print(action_line(actually, "Delete inline policy from role", f"{policy_name} from {role_name}"))
                        if actually:
                            safe_call(iam.delete_role_policy, RoleName=role_name, PolicyName=policy_name)
                except ClientError:
                    pass
                
                # Remove role from instance profiles
                try:
                    instance_profiles = iam.list_instance_profiles_for_role(RoleName=role_name).get("InstanceProfiles", [])
                    for profile in instance_profiles:
                        profile_name = profile["InstanceProfileName"]
                        print(action_line(actually, "Remove role from instance profile", f"{role_name} from {profile_name}"))
                        if actually:
                            safe_call(iam.remove_role_from_instance_profile, InstanceProfileName=profile_name, RoleName=role_name)
                except ClientError:
                    pass
                
                # Finally delete the role
                print(action_line(actually, "Delete IAM Role", f"{role_name}"))
                if actually:
                    safe_call(iam.delete_role, RoleName=role_name)
    except ClientError:
        pass
    
    # Get all customer-managed policies (exclude AWS-managed)
    try:
        paginator = iam.get_paginator("list_policies")
        policies = []
        for page in paginator.paginate(Scope="Local"):  # Local = customer-managed
            policies.extend(page.get("Policies", []))
    except ClientError:
        policies = []
    
    for policy in policies:
        policy_arn = policy["Arn"]
        policy_name = policy["PolicyName"]
        
        print(action_line(actually, "IAM Policy cleanup", f"{policy_name} ({policy_arn})"))
        
        # Detach from roles
        try:
            roles = iam.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter="Role").get("PolicyRoles", [])
            for role in roles:
                role_name = role["RoleName"]
                print(action_line(actually, "Detach policy from role", f"{policy_name} from {role_name}"))
                if actually:
                    safe_call(iam.detach_role_policy, RoleName=role_name, PolicyArn=policy_arn)
        except ClientError:
            pass
        
        # Detach from users
        try:
            users = iam.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter="User").get("PolicyUsers", [])
            for user in users:
                user_name = user["UserName"]
                print(action_line(actually, "Detach policy from user", f"{policy_name} from {user_name}"))
                if actually:
                    safe_call(iam.detach_user_policy, UserName=user_name, PolicyArn=policy_arn)
        except ClientError:
            pass
        
        # Detach from groups
        try:
            groups = iam.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter="Group").get("PolicyGroups", [])
            for group in groups:
                group_name = group["GroupName"]
                print(action_line(actually, "Detach policy from group", f"{policy_name} from {group_name}"))
                if actually:
                    safe_call(iam.detach_group_policy, GroupName=group_name, PolicyArn=policy_arn)
        except ClientError:
            pass
        
        # Delete all non-default policy versions
        try:
            versions = iam.list_policy_versions(PolicyArn=policy_arn).get("Versions", [])
            for version in versions:
                if not version.get("IsDefaultVersion", False):
                    version_id = version["VersionId"]
                    print(action_line(actually, "Delete policy version", f"{policy_name} v{version_id}"))
                    if actually:
                        safe_call(iam.delete_policy_version, PolicyArn=policy_arn, VersionId=version_id)
        except ClientError:
            pass
        
        # Finally delete the policy
        print(action_line(actually, "Delete IAM Policy", f"{policy_name} ({policy_arn})"))
        if actually:
            safe_call(iam.delete_policy, PolicyArn=policy_arn)

# ---------------- Route 53 (global) ----------------
def route53_delete_rrsets_except_apex_ns_soa(r53, hosted_zone_id: str, zone_name_with_dot: str, actually: bool):
    paginator = r53.get_paginator("list_resource_record_sets")
    changes = []

    def flush_changes():
        nonlocal changes
        if not changes:
            return
        if actually:
            r53.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch={"Comment":"Zone cleanup","Changes":changes},
            )
        else:
            for ch in changes:
                rr = ch["ResourceRecordSet"]
                print(action_line(False, "Delete RRSet", f"{zone_name_with_dot} {rr.get('Type')} {rr.get('Name')}"))
        changes = []

    for page in paginator.paginate(HostedZoneId=hosted_zone_id):
        for rr in page["ResourceRecordSets"]:
            name, rtype = rr["Name"], rr["Type"]
            if (name == zone_name_with_dot) and (rtype in ("NS","SOA")):
                continue
            changes.append({"Action":"DELETE","ResourceRecordSet":rr})
            if len(changes) == 100:
                flush_changes()
    flush_changes()

def route53_disable_dnssec_if_enabled(r53, hosted_zone_id: str, actually: bool):
    try:
        dnssec = r53.get_dnssec(HostedZoneId=hosted_zone_id)
        status = dnssec.get("Status", {}).get("ServeSignature")
        if status == "SIGNING":
            print(action_line(actually, "Disable DNSSEC", hosted_zone_id))
            if actually:
                r53.disable_hosted_zone_dnssec(HostedZoneId=hosted_zone_id)
    except ClientError:
        pass

def route53_disassociate_all_vpcs_if_private(r53, hosted_zone_id: str, actually: bool):
    try:
        hz = r53.get_hosted_zone(Id=hosted_zone_id)
    except ClientError as e:
        print(f"  ! {e}", file=sys.stderr); return
    if hz["HostedZone"]["Config"].get("PrivateZone"):
        for v in hz.get("VPCs", []):
            msg = f"{hosted_zone_id} VPC {v['VPCId']} ({v['VPCRegion']})"
            print(action_line(actually, "Disassociate VPC from Private Hosted Zone", msg))
            if actually:
                safe_call(
                    r53.disassociate_vpc_from_hosted_zone,
                    HostedZoneId=hosted_zone_id,
                    VPC={"VPCRegion":v["VPCRegion"],"VPCId":v["VPCId"]},
                )

def cleanup_route53(actually: bool):
    r53 = boto3.client("route53", config=CFG)
    paginator = r53.get_paginator("list_hosted_zones")
    for page in paginator.paginate():
        for hz in page["HostedZones"]:
            hz_id = hz["Id"].split("/")[-1]
            zone_name = hz["Name"]
            print(action_line(actually, "Route53 Hosted Zone cleanup", f"{zone_name} ({hz_id})"))
            route53_disable_dnssec_if_enabled(r53, hz_id, actually)
            route53_delete_rrsets_except_apex_ns_soa(r53, hz_id, zone_name, actually)
            route53_disassociate_all_vpcs_if_private(r53, hz_id, actually)
            print(action_line(actually, "Delete Hosted Zone", f"{zone_name} ({hz_id})"))
            if actually:
                safe_call(r53.delete_hosted_zone, Id=hz_id)

# ---------------- Orchestration ----------------
def per_region_worker(region: str, actually: bool, rds_final_snapshot_prefix: str|None):
    print(f"\n=== Region: {region} ===")
    # Compute first
    cleanup_ec2(region, actually)
    cleanup_lambda(region, actually)

    # Container/orchestrators before network teardown
    cleanup_eks(region, actually)

    # Storage/registries/logs
    cleanup_s3(region, actually)
    cleanup_ecr(region, actually)
    cleanup_logs(region, actually)

    # Load balancers (depend on subnets)
    cleanup_elbv2(region, actually)
    cleanup_elb_classic(region, actually)

    # RDS (before killing VPC)
    cleanup_rds(region, actually, rds_final_snapshot_prefix)

    # Network interfaces & SGs (to unblock VPC)
    cleanup_enis(region, actually)
    cleanup_security_groups(region, actually)

    # VPC teardown (last)
    cleanup_vpcs(region, actually)

    return region

def main():
    parser = argparse.ArgumentParser(description="Dangerous account cleanup — DRY-RUN by default.")
    parser.add_argument("--really-delete", action="store_true", help="Actually perform deletions.")
    parser.add_argument("--regions", nargs="*", help="Limit to these regions (default: all).")
    parser.add_argument("--include-route53", action="store_true", help="Include Route 53 hosted zone deletions (global).")
    parser.add_argument("--include-iam", action="store_true", help="Include IAM customer-managed policy deletions (global).")
    parser.add_argument("--rds-final-snapshot-prefix", help="If set, create final RDS snapshots with this prefix (else SkipFinalSnapshot=True).")
    args = parser.parse_args()

    acct = confirm_account()
    print(f"Account: {acct}")

    target_regions = args.regions or regions()
    print(f"Regions: {', '.join(target_regions)}")
    if not args.really_delete:
        print("MODE: DRY-RUN (no delete calls will be made)")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(per_region_worker, r, args.really_delete, args.rds_final_snapshot_prefix) for r in target_regions]
        for f in as_completed(futures):
            _ = f.result()

    if args.include_route53:
        print("\n=== Global: Route 53 ===")
        cleanup_route53(args.really_delete)

    if args.include_iam:
        print("\n=== Global: IAM ===")
        cleanup_iam(args.really_delete)

    print("\nDone.")

if __name__ == "__main__":
    main()