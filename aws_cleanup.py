#!/usr/bin/env python3
"""
AWS Cleanup Script (DRY-RUN by default)

Per-region cleanup:
- EC2: Auto Scaling Groups, instances, available EBS volumes, AMIs (+ snapshots), loose snapshots, Elastic IPs, key pairs
- Lambda: functions
- S3: empties versioned/unversioned buckets then deletes them (bucket-region aware)
- ECR: repositories (force delete images)
- CloudWatch Logs: log groups
- CloudWatch: alarms, dashboards
- ACM: SSL/TLS certificates
- API Gateway: REST APIs, HTTP APIs, WebSocket APIs, custom domains
- DynamoDB: tables, global tables, backups
- SQS: queues (standard and FIFO)
- SNS: topics and subscriptions
- ENI: deletes 'available' network interfaces
- Security Groups: revokes rules, removes cross-references, deletes non-default SGs
- Load Balancers: ALB/NLB (ELBv2) + Classic ELB, target groups
- VPC teardown (best-effort, order-aware): endpoints, ELBs, NAT GWs, IGWs (detach), subnets, non-main route tables, non-default NACLs, peering, VPN attachments/GWs, then VPC
- RDS: DB clusters & instances (removes deletion protection), snapshots, subnet groups
- ECS: Capacity Providers, clusters
- EKS: add-ons, fargate profiles, nodegroups, clusters; tries to remove IAM OIDC provider

Global (opt-in):
- Route 53: disable DNSSEC (if enabled), delete ALL record sets except apex NS/SOA, disassociate VPCs (private zones), then delete hosted zones
- IAM: deletes identity providers (OIDC/SAML, excludes those with "aws" or "DO_NOT_DELETE" in name), deletes roles (excludes those starting with "AWS"), deletes instance profiles, detaches and deletes customer-managed policies

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

# Optional GUI support - will fallback to CLI if not available
try:
    import inquirer
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

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
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        print(f"    {warning_line(f'{error_code}: {error_msg}')}", file=sys.stderr)
        return None

def action_line(actually: bool, verb: str, resource: str) -> str:
    """Format action line for consistent logging with clean aesthetics"""
    if actually:
        prefix = "🗑️"
        color = "\033[91m"  # Red
    else:
        prefix = "📋"
        color = "\033[94m"  # Blue
    
    reset = "\033[0m"  # Reset color
    # Clean format: emoji + action + resource
    return f"  {color}{prefix} {verb}{reset}: {resource}"

def success_line(message: str) -> str:
    """Format success line for completed actions"""
    return f"\033[92m✅ {message}\033[0m"

def error_line(message: str) -> str:
    """Format error line for failed actions"""
    return f"\033[91m❌ {message}\033[0m"

def info_line(message: str) -> str:
    """Format info line for general information"""
    return f"\033[96m💡 {message}\033[0m"

def warning_line(message: str) -> str:
    """Format warning line for important notices"""
    return f"\033[93m⚠️  {message}\033[0m"

def section_header(title: str) -> str:
    """Format clean section header"""
    return f"\n\033[95m{'─' * 60}\033[0m\n\033[95m✨ {title}\033[0m\n\033[95m{'─' * 60}\033[0m"

def service_header(service: str, region: str = None) -> str:
    """Format service header with clean styling"""
    location = f" ({region})" if region else ""
    return f"\n\033[96m🔧 {service}{location}\033[0m"

def summary_item(label: str, value: str) -> str:
    """Format summary items consistently"""
    return f"   • {label}: \033[97m{value}\033[0m"

def skip_message(resource: str, reason: str) -> str:
    """Format skip messages cleanly"""
    return f"  \033[90m⏭️  Skipping {resource} ({reason})\033[0m"

def count_message(service: str, count: int, resource_type: str) -> str:
    """Format resource count messages"""
    if count == 0:
        return f"  \033[90m📭 No {resource_type} found in {service}\033[0m"
    else:
        return f"  \033[94m📊 Found {count} {resource_type} in {service}\033[0m"

# ---------------- Auto Scaling Groups ----------------
def cleanup_autoscaling(region: str, actually: bool):
    asg = boto3.client("autoscaling", region_name=region, config=CFG)
    
    try:
        paginator = asg.get_paginator("describe_auto_scaling_groups")
        for page in paginator.paginate():
            for group in page.get("AutoScalingGroups", []):
                group_name = group["AutoScalingGroupName"]
                
                print(action_line(actually, "Auto Scaling Group cleanup", f"{region} {group_name}"))
                
                # Set desired capacity to 0 first to terminate instances gracefully
                if group["DesiredCapacity"] > 0:
                    print(action_line(actually, "Set ASG desired capacity to 0", f"{region} {group_name}"))
                    if actually:
                        safe_call(asg.update_auto_scaling_group, 
                                AutoScalingGroupName=group_name,
                                DesiredCapacity=0,
                                MinSize=0)
                        
                        # Wait a bit for instances to start terminating
                        print(f"  Waiting for ASG {group_name} instances to terminate...")
                        time.sleep(15)
                
                # Delete the Auto Scaling Group
                print(action_line(actually, "Delete Auto Scaling Group", f"{region} {group_name}"))
                if actually:
                    safe_call(asg.delete_auto_scaling_group, 
                            AutoScalingGroupName=group_name,
                            ForceDelete=True)  # Force delete to handle remaining instances
    except ClientError:
        pass

# ---------------- ECS (Elastic Container Service) ----------------
def cleanup_ecs(region: str, actually: bool):
    ecs = boto3.client("ecs", region_name=region, config=CFG)
    
    # Delete ECS Clusters first (this will also delete services and tasks)
    try:
        paginator = ecs.get_paginator("list_clusters")
        for page in paginator.paginate():
            for cluster_arn in page.get("clusterArns", []):
                cluster_name = cluster_arn.split("/")[-1]
                
                print(action_line(actually, "ECS Cluster cleanup", f"{region} {cluster_name}"))
                
                # List and stop all services in the cluster
                try:
                    services_paginator = ecs.get_paginator("list_services")
                    for services_page in services_paginator.paginate(cluster=cluster_arn):
                        for service_arn in services_page.get("serviceArns", []):
                            service_name = service_arn.split("/")[-1]
                            print(action_line(actually, "Delete ECS Service", f"{region} {cluster_name}/{service_name}"))
                            if actually:
                                # Set desired count to 0 first, then delete
                                safe_call(ecs.update_service, cluster=cluster_arn, service=service_arn, desiredCount=0)
                                safe_call(ecs.delete_service, cluster=cluster_arn, service=service_arn)
                except ClientError:
                    pass
                
                # Delete the cluster
                print(action_line(actually, "Delete ECS Cluster", f"{region} {cluster_name}"))
                if actually:
                    safe_call(ecs.delete_cluster, cluster=cluster_arn)
    except ClientError:
        pass
    
    # Delete ECS Capacity Providers
    try:
        response = ecs.describe_capacity_providers()
        for cp in response.get("capacityProviders", []):
            cp_name = cp["name"]
            
            # Skip AWS-managed capacity providers
            if cp_name.startswith("FARGATE"):
                print(skip_message(f"capacity provider {cp_name}", "AWS-managed"))
                continue
            
            print(action_line(actually, "Delete ECS Capacity Provider", f"{region} {cp_name}"))
            if actually:
                safe_call(ecs.delete_capacity_provider, capacityProvider=cp_name)
    except ClientError:
        pass

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

# ---------------- CloudWatch ----------------
def cleanup_cloudwatch(region: str, actually: bool):
    cloudwatch = boto3.client("cloudwatch", region_name=region, config=CFG)
    
    # Delete CloudWatch Alarms
    try:
        paginator = cloudwatch.get_paginator("describe_alarms")
        for page in paginator.paginate():
            for alarm in page.get("MetricAlarms", []):
                alarm_name = alarm["AlarmName"]
                print(action_line(actually, "Delete CloudWatch Alarm", f"{region} {alarm_name}"))
                if actually:
                    safe_call(cloudwatch.delete_alarms, AlarmNames=[alarm_name])
            
            # Composite alarms
            for alarm in page.get("CompositeAlarms", []):
                alarm_name = alarm["AlarmName"]
                print(action_line(actually, "Delete CloudWatch Composite Alarm", f"{region} {alarm_name}"))
                if actually:
                    safe_call(cloudwatch.delete_alarms, AlarmNames=[alarm_name])
    except ClientError:
        pass
    
    # Delete CloudWatch Dashboards
    try:
        paginator = cloudwatch.get_paginator("list_dashboards")
        for page in paginator.paginate():
            for dashboard in page.get("DashboardEntries", []):
                dashboard_name = dashboard["DashboardName"]
                print(action_line(actually, "Delete CloudWatch Dashboard", f"{region} {dashboard_name}"))
                if actually:
                    safe_call(cloudwatch.delete_dashboards, DashboardNames=[dashboard_name])
    except ClientError:
        pass

# ---------------- API Gateway ----------------
def cleanup_apigateway(region: str, actually: bool):
    apigateway = boto3.client("apigateway", region_name=region, config=CFG)
    apigatewayv2 = boto3.client("apigatewayv2", region_name=region, config=CFG)
    
    # Delete REST APIs (API Gateway v1)
    try:
        paginator = apigateway.get_paginator("get_rest_apis")
        for page in paginator.paginate():
            for api in page.get("items", []):
                api_id = api["id"]
                api_name = api.get("name", "unknown")
                print(action_line(actually, "Delete API Gateway REST API", f"{region} {api_name} ({api_id})"))
                if actually:
                    safe_call(apigateway.delete_rest_api, restApiId=api_id)
    except ClientError:
        pass
    
    # Delete HTTP APIs and WebSocket APIs (API Gateway v2)
    try:
        paginator = apigatewayv2.get_paginator("get_apis")
        for page in paginator.paginate():
            for api in page.get("Items", []):
                api_id = api["ApiId"]
                api_name = api.get("Name", "unknown")
                protocol_type = api.get("ProtocolType", "unknown")
                print(action_line(actually, f"Delete API Gateway {protocol_type} API", f"{region} {api_name} ({api_id})"))
                if actually:
                    safe_call(apigatewayv2.delete_api, ApiId=api_id)
    except ClientError:
        pass
    
    # Delete Custom Domain Names (v1)
    try:
        paginator = apigateway.get_paginator("get_domain_names")
        for page in paginator.paginate():
            for domain in page.get("items", []):
                domain_name = domain["domainName"]
                print(action_line(actually, "Delete API Gateway Domain Name", f"{region} {domain_name}"))
                if actually:
                    safe_call(apigateway.delete_domain_name, domainName=domain_name)
    except ClientError:
        pass
    
    # Delete Custom Domain Names (v2)
    try:
        paginator = apigatewayv2.get_paginator("get_domain_names")
        for page in paginator.paginate():
            for domain in page.get("Items", []):
                domain_name = domain["DomainName"]
                print(action_line(actually, "Delete API Gateway v2 Domain Name", f"{region} {domain_name}"))
                if actually:
                    safe_call(apigatewayv2.delete_domain_name, DomainName=domain_name)
    except ClientError:
        pass

# ---------------- DynamoDB ----------------
def cleanup_dynamodb(region: str, actually: bool):
    dynamodb = boto3.client("dynamodb", region_name=region, config=CFG)
    
    # Delete DynamoDB Tables
    try:
        paginator = dynamodb.get_paginator("list_tables")
        for page in paginator.paginate():
            for table_name in page.get("TableNames", []):
                print(action_line(actually, "Delete DynamoDB Table", f"{region} {table_name}"))
                if actually:
                    # Remove deletion protection if enabled
                    try:
                        table_info = dynamodb.describe_table(TableName=table_name)
                        if table_info.get("Table", {}).get("DeletionProtectionEnabled", False):
                            print(action_line(actually, "Disable DynamoDB deletion protection", f"{region} {table_name}"))
                            safe_call(dynamodb.update_table, 
                                    TableName=table_name,
                                    DeletionProtectionEnabled=False)
                    except ClientError:
                        pass
                    
                    safe_call(dynamodb.delete_table, TableName=table_name)
    except ClientError:
        pass
    
    # Delete DynamoDB Backups
    try:
        paginator = dynamodb.get_paginator("list_backups")
        for page in paginator.paginate():
            for backup in page.get("BackupSummaries", []):
                backup_arn = backup["BackupArn"]
                backup_name = backup.get("BackupName", "unknown")
                if backup["BackupStatus"] == "AVAILABLE":
                    print(action_line(actually, "Delete DynamoDB Backup", f"{region} {backup_name} ({backup_arn})"))
                    if actually:
                        safe_call(dynamodb.delete_backup, BackupArn=backup_arn)
    except ClientError:
        pass

# ---------------- SQS ----------------
def cleanup_sqs(region: str, actually: bool):
    sqs = boto3.client("sqs", region_name=region, config=CFG)
    
    try:
        paginator = sqs.get_paginator("list_queues")
        for page in paginator.paginate():
            for queue_url in page.get("QueueUrls", []):
                queue_name = queue_url.split("/")[-1]
                print(action_line(actually, "Delete SQS Queue", f"{region} {queue_name}"))
                if actually:
                    safe_call(sqs.delete_queue, QueueUrl=queue_url)
    except ClientError:
        pass

# ---------------- SNS ----------------
def cleanup_sns(region: str, actually: bool):
    sns = boto3.client("sns", region_name=region, config=CFG)
    
    # Delete SNS Topics
    try:
        paginator = sns.get_paginator("list_topics")
        for page in paginator.paginate():
            for topic in page.get("Topics", []):
                topic_arn = topic["TopicArn"]
                topic_name = topic_arn.split(":")[-1]
                print(action_line(actually, "Delete SNS Topic", f"{region} {topic_name} ({topic_arn})"))
                if actually:
                    safe_call(sns.delete_topic, TopicArn=topic_arn)
    except ClientError:
        pass

# ---------------- ACM (Certificate Manager) ----------------
def cleanup_acm(region: str, actually: bool):
    acm = boto3.client("acm", region_name=region, config=CFG)
    
    try:
        paginator = acm.get_paginator("list_certificates")
        for page in paginator.paginate():
            for cert in page.get("CertificateSummaryList", []):
                cert_arn = cert["CertificateArn"]
                domain_name = cert.get("DomainName", "unknown")
                
                # Check what resources are using this certificate and delete them first
                try:
                    cert_details = acm.describe_certificate(CertificateArn=cert_arn)
                    in_use_by = cert_details.get("Certificate", {}).get("InUseBy", [])
                    
                    if in_use_by:
                        print(action_line(actually, "ACM Certificate in use, deleting dependent resources", f"{region} {domain_name} (used by {len(in_use_by)} resources)"))
                        
                        for resource_arn in in_use_by:
                            delete_resource_using_certificate(region, resource_arn, actually)
                except ClientError:
                    pass
                
                print(action_line(actually, "Delete ACM Certificate", f"{region} {domain_name} ({cert_arn})"))
                if actually:
                    safe_call(acm.delete_certificate, CertificateArn=cert_arn)
    except ClientError:
        pass

def delete_resource_using_certificate(region: str, resource_arn: str, actually: bool):
    """Delete resources that are using ACM certificates"""
    try:
        # Parse the ARN to determine resource type
        arn_parts = resource_arn.split(":")
        if len(arn_parts) < 6:
            return
        
        service = arn_parts[2]
        resource_type_and_id = arn_parts[5]
        
        if service == "elasticloadbalancing":
            # ELB/ALB/NLB
            if "loadbalancer/" in resource_type_and_id:
                lb_arn = resource_arn
                print(action_line(actually, "Delete Load Balancer (using certificate)", f"{region} {lb_arn}"))
                if actually:
                    if "app/" in resource_type_and_id or "net/" in resource_type_and_id:
                        # ALB/NLB
                        elbv2 = boto3.client("elbv2", region_name=region, config=CFG)
                        safe_call(elbv2.delete_load_balancer, LoadBalancerArn=lb_arn)
                    else:
                        # Classic ELB
                        elb = boto3.client("elb", region_name=region, config=CFG)
                        lb_name = resource_type_and_id.split("/")[-1]
                        safe_call(elb.delete_load_balancer, LoadBalancerName=lb_name)
        
        elif service == "cloudfront":
            # CloudFront Distribution
            distribution_id = resource_type_and_id.split("/")[-1]
            print(action_line(actually, "Delete CloudFront Distribution (using certificate)", f"{region} {distribution_id}"))
            if actually:
                cloudfront = boto3.client("cloudfront", config=CFG)
                try:
                    # Get distribution config first
                    resp = cloudfront.get_distribution_config(Id=distribution_id)
                    config = resp["DistributionConfig"]
                    etag = resp["ETag"]
                    
                    # Disable distribution first
                    config["Enabled"] = False
                    cloudfront.update_distribution(Id=distribution_id, DistributionConfig=config, IfMatch=etag)
                    print(f"  CloudFront distribution {distribution_id} disabled, will need manual deletion after propagation")
                except ClientError as e:
                    print(f"  ! Failed to disable CloudFront distribution {distribution_id}: {e}", file=sys.stderr)
        
        elif service == "apigateway":
            # API Gateway Custom Domain
            if "domainnames/" in resource_type_and_id:
                domain_name = resource_type_and_id.split("/")[-1]
                print(action_line(actually, "Delete API Gateway Domain Name (using certificate)", f"{region} {domain_name}"))
                if actually:
                    apigateway = boto3.client("apigateway", region_name=region, config=CFG)
                    safe_call(apigateway.delete_domain_name, domainName=domain_name)
        
        else:
            print(f"  ! Unknown resource type using certificate: {resource_arn}", file=sys.stderr)
    
    except Exception as e:
        print(f"  ! Failed to delete resource using certificate {resource_arn}: {e}", file=sys.stderr)

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

        # Release any remaining Elastic IPs in this VPC first
        try:
            addrs = ec2.describe_addresses()["Addresses"]
            for a in addrs:
                # Check if EIP is associated with resources in this VPC
                if a.get("NetworkInterfaceId") or a.get("InstanceId"):
                    try:
                        vpc_match = False
                        if a.get("NetworkInterfaceId"):
                            eni = ec2.describe_network_interfaces(NetworkInterfaceIds=[a["NetworkInterfaceId"]])["NetworkInterfaces"][0]
                            vpc_match = eni.get("VpcId") == vpc_id
                        elif a.get("InstanceId"):
                            inst = ec2.describe_instances(InstanceIds=[a["InstanceId"]])["Reservations"][0]["Instances"][0]
                            vpc_match = inst.get("VpcId") == vpc_id
                        
                        if vpc_match:
                            alloc = a.get("AllocationId")
                            if alloc:
                                print(action_line(actually, "Release Elastic IP (VPC cleanup)", f"{region} {alloc}"))
                                if actually:
                                    safe_call(ec2.release_address, AllocationId=alloc)
                    except ClientError:
                        pass
        except ClientError:
            pass

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
            ngw = ec2.describe_nat_gateways(Filters=[{"Name":"vpc-id","Values":[vpc_id]}])["NatGateways"]
            for n in ngw:
                if n.get("State") not in ("deleted", "deleting"):
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
                            print(f"  Subnet group {name} still in use, waiting 2min (attempt {attempt + 1}/3)...")
                            time.sleep(120)
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
    
    # Delete IAM instance profiles
    try:
        paginator = iam.get_paginator("list_instance_profiles")
        for page in paginator.paginate():
            for profile in page.get("InstanceProfiles", []):
                profile_name = profile["InstanceProfileName"]
                
                print(action_line(actually, "IAM Instance Profile cleanup", f"{profile_name}"))
                
                # Remove all roles from the instance profile first
                for role in profile.get("Roles", []):
                    role_name = role["RoleName"]
                    print(action_line(actually, "Remove role from instance profile", f"{role_name} from {profile_name}"))
                    if actually:
                        safe_call(iam.remove_role_from_instance_profile, InstanceProfileName=profile_name, RoleName=role_name)
                
                # Delete the instance profile
                print(action_line(actually, "Delete IAM Instance Profile", f"{profile_name}"))
                if actually:
                    safe_call(iam.delete_instance_profile, InstanceProfileName=profile_name)
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
            print(action_line(actually, "Delete DNS records", f"{len(changes)} records from {zone_name_with_dot}"))
            safe_call(r53.change_resource_record_sets,
                HostedZoneId=hosted_zone_id,
                ChangeBatch={"Comment": "Zone cleanup", "Changes": changes}
            )
        else:
            print(action_line(False, "Delete DNS records", f"{len(changes)} records from {zone_name_with_dot}"))
        changes = []

    try:
        for page in paginator.paginate(HostedZoneId=hosted_zone_id):
            for rr in page["ResourceRecordSets"]:
                name, rtype = rr["Name"], rr["Type"]
                # Skip apex NS and SOA records (required for the zone)
                if (name == zone_name_with_dot) and (rtype in ("NS", "SOA")):
                    continue  # Skip silently - these are required
                
                changes.append({"Action": "DELETE", "ResourceRecordSet": rr})
                
                # Batch changes to avoid API limits
                if len(changes) >= 100:
                    flush_changes()
        
        # Delete any remaining changes
        flush_changes()
        
    except ClientError as e:
        print(warning_line(f"Error processing Route53 record sets: {e}"))
        # Try to flush any pending changes before giving up
        if changes:
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

            # Give Route 53 a moment to process record deletions before deleting the zone
            if actually:
                print(info_line("Waiting for DNS changes to propagate..."))
                time.sleep(5)
            
            print(action_line(actually, "Delete Hosted Zone", f"{zone_name} ({hz_id})"))
            if actually:
                safe_call(r53.delete_hosted_zone, Id=hz_id)

# ---------------- Service Selection Logic ----------------
def get_services_to_run(args):
    """Determine which services to run based on command line arguments"""
    
    # Resource type mappings
    resource_type_mapping = {
        "compute": ["autoscaling", "ec2", "lambda"],
        "storage": ["s3", "ecr", "dynamodb"],
        "network": ["elbv2", "elb", "enis", "security-groups", "vpcs"],
        "database": ["rds", "dynamodb"],
        "security": ["iam"],
        "containers": ["ecs", "eks", "ecr"],
        "messaging": ["sqs", "sns"],
        "api": ["apigateway"],
        "monitoring": ["logs", "cloudwatch"]
    }
    
    regional_services = []
    global_services = []
    
    if args.services:
        regional_services = args.services
    elif args.global_services:
        global_services = args.global_services
    elif args.resource_types:
        for resource_type in args.resource_types:
            if resource_type in resource_type_mapping:
                regional_services.extend(resource_type_mapping[resource_type])
        # Remove duplicates while preserving order
        regional_services = list(dict.fromkeys(regional_services))
        # Handle global services for security type
        if "security" in args.resource_types:
            global_services = ["iam"]
    elif args.all_global:
        global_services = ["route53", "iam"]
    elif args.all_resources:
        regional_services = ["autoscaling", "ec2", "lambda", "ecs", "eks", "s3", "ecr", "logs", "cloudwatch", 
                           "acm", "apigateway", "dynamodb", "sqs", "sns", "elbv2", "elb", "rds", 
                           "enis", "security-groups", "vpcs"]
        global_services = ["route53", "iam"]
    else:
        # Default: all resources (regional + global)
        regional_services = ["autoscaling", "ec2", "lambda", "ecs", "eks", "s3", "ecr", "logs", "cloudwatch", 
                           "acm", "apigateway", "dynamodb", "sqs", "sns", "elbv2", "elb", "rds", 
                           "enis", "security-groups", "vpcs"]
        global_services = ["route53", "iam"]
    
    return regional_services, global_services

# ---------------- Orchestration ----------------
def per_region_worker(region: str, actually: bool, rds_final_snapshot_prefix: str|None, selected_services: list):
    print(service_header(f"🌍 Region: {region}"))
    
    # Service execution mapping with proper dependency order
    service_functions = {
        # Compute first (ASG before EC2 to handle dependencies)
        "autoscaling": lambda: cleanup_autoscaling(region, actually),
        "ec2": lambda: cleanup_ec2(region, actually),
        "lambda": lambda: cleanup_lambda(region, actually),
        
        # Container/orchestrators before network teardown
        "ecs": lambda: cleanup_ecs(region, actually),
        "eks": lambda: cleanup_eks(region, actually),
        
        # Storage/registries/logs
        "s3": lambda: cleanup_s3(region, actually),
        "ecr": lambda: cleanup_ecr(region, actually),
        "logs": lambda: cleanup_logs(region, actually),
        "cloudwatch": lambda: cleanup_cloudwatch(region, actually),
        "acm": lambda: cleanup_acm(region, actually),
        
        # APIs and messaging
        "apigateway": lambda: cleanup_apigateway(region, actually),
        "dynamodb": lambda: cleanup_dynamodb(region, actually),
        "sqs": lambda: cleanup_sqs(region, actually),
        "sns": lambda: cleanup_sns(region, actually),
        
        # Load balancers (depend on subnets)
        "elbv2": lambda: cleanup_elbv2(region, actually),
        "elb": lambda: cleanup_elb_classic(region, actually),
        
        # Databases
        "rds": lambda: cleanup_rds(region, actually, rds_final_snapshot_prefix),
        
        # Network interfaces & SGs (to unblock VPC)
        "enis": lambda: cleanup_enis(region, actually),
        "security-groups": lambda: cleanup_security_groups(region, actually),
        
        # VPC teardown (last)
        "vpcs": lambda: cleanup_vpcs(region, actually)
    }
    
    # Execute selected services in dependency order
    execution_order = ["autoscaling", "ec2", "lambda", "ecs", "eks", "s3", "ecr", "logs", "cloudwatch", 
                      "acm", "apigateway", "dynamodb", "sqs", "sns", "elbv2", "elb", "rds", 
                      "enis", "security-groups", "vpcs"]
    
    for service in execution_order:
        if service in selected_services and service in service_functions:
            service_functions[service]()

    return region

# ---------------- Interactive GUI Functions ----------------
def show_interactive_menu():
    """Show interactive GUI menu for service selection"""
    if not GUI_AVAILABLE:
        print(f"\n{error_line('Interactive mode not available - Missing inquirer library')}")
        print(info_line("Install with: pip install inquirer"))
        print(info_line("Falling back to command-line mode. Use --help for options."))
        return None
    
    print(f"\n{section_header('🚀 AWS CLEANUP TOOL - INTERACTIVE MODE')}")
    print(info_line("Use arrow keys to navigate, space to select/deselect, enter to confirm"))
    print()
    
    # Main selection type
    selection_type = inquirer.list_input(
        "How would you like to select services?",
        choices=[
            ("Select specific services", "services"),
            ("Select by resource type", "resource-types"),
            ("Select all regional services", "all-regional"),
            ("Select all global services", "all-global"),
            ("Select all services (regional + global)", "all-resources"),
            ("Exit", "exit")
        ]
    )
    
    if selection_type == "exit":
        print("👋 Goodbye!")
        sys.exit(0)
    
    # Service mappings
    all_regional_services = [
        ("Auto Scaling Groups", "autoscaling"),
        ("EC2 Instances & Resources", "ec2"),
        ("Lambda Functions", "lambda"),
        ("ECS (Containers)", "ecs"),
        ("EKS (Kubernetes)", "eks"),
        ("S3 Buckets", "s3"),
        ("ECR Repositories", "ecr"),
        ("CloudWatch Logs", "logs"),
        ("CloudWatch Alarms & Dashboards", "cloudwatch"),
        ("ACM Certificates", "acm"),
        ("API Gateway", "apigateway"),
        ("DynamoDB Tables", "dynamodb"),
        ("SQS Queues", "sqs"),
        ("SNS Topics", "sns"),
        ("Load Balancers (ALB/NLB)", "elbv2"),
        ("Classic Load Balancers", "elb"),
        ("RDS Databases", "rds"),
        ("Network Interfaces (ENI)", "enis"),
        ("Security Groups", "security-groups"),
        ("VPCs", "vpcs")
    ]
    
    all_global_services = [
        ("Route 53 DNS", "route53"),
        ("IAM (Policies, Roles, etc.)", "iam")
    ]
    
    resource_types = [
        ("Compute (ASG, EC2, Lambda)", "compute"),
        ("Storage (S3, ECR, DynamoDB)", "storage"),
        ("Network (LB, ENI, SG, VPC)", "network"),
        ("Database (RDS, DynamoDB)", "database"),
        ("Security (IAM)", "security"),
        ("Containers (ECS, EKS, ECR)", "containers"),
        ("Messaging (SQS, SNS)", "messaging"),
        ("API (API Gateway)", "api"),
        ("Monitoring (CloudWatch, Logs)", "monitoring")
    ]
    
    selected_services = []
    selected_global_services = []
    
    if selection_type == "services":
        # Multi-select regional services
        selected_services = inquirer.checkbox(
            "Select regional services to clean up",
            choices=all_regional_services
        )
        
        # Ask about global services
        include_global = inquirer.confirm("Also include global services?", default=False)
        if include_global:
            selected_global_services = inquirer.checkbox(
                "Select global services to clean up",
                choices=all_global_services
            )
    
    elif selection_type == "resource-types":
        selected_types = inquirer.checkbox(
            "Select resource types to clean up",
            choices=resource_types
        )
        
        # Map resource types to services
        resource_type_mapping = {
            "compute": ["autoscaling", "ec2", "lambda"],
            "storage": ["s3", "ecr", "dynamodb"],
            "network": ["elbv2", "elb", "enis", "security-groups", "vpcs"],
            "database": ["rds", "dynamodb"],
            "security": ["iam"],
            "containers": ["ecs", "eks", "ecr"],
            "messaging": ["sqs", "sns"],
            "api": ["apigateway"],
            "monitoring": ["logs", "cloudwatch"]
        }
        
        selected_services = []
        for resource_type in selected_types:
            selected_services.extend(resource_type_mapping.get(resource_type, []))
        
        # Remove duplicates and handle global services
        selected_services = list(set(selected_services))
        if "iam" in selected_services:
            selected_services.remove("iam")
            selected_global_services = ["iam"]
    
    elif selection_type == "all-regional":
        selected_services = [service[1] for service in all_regional_services]
    
    elif selection_type == "all-global":
        selected_global_services = [service[1] for service in all_global_services]
    
    elif selection_type == "all-resources":
        selected_services = [service[1] for service in all_regional_services]
        selected_global_services = [service[1] for service in all_global_services]
    
    # Additional options
    print()
    dry_run = inquirer.confirm("DRY-RUN mode? (Recommended - shows what would be deleted without actually deleting)", default=True)
    
    # Region selection
    print()
    all_regions = inquirer.confirm("Clean up in ALL AWS regions?", default=True)
    selected_regions = None
    if not all_regions:
        common_regions = [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-central-1",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1"
        ]
        selected_regions = inquirer.checkbox(
            "Select specific regions",
            choices=common_regions
        )
    
    # RDS snapshot option
    rds_snapshot_prefix = None
    if "rds" in selected_services:
        create_snapshots = inquirer.confirm("Create final RDS snapshots before deletion?", default=False)
        if create_snapshots:
            rds_snapshot_prefix = inquirer.text("Enter snapshot prefix", default="cleanup-final")
    
    # Summary
    print(section_header("CLEANUP SUMMARY"))
    
    if dry_run:
        print(info_line("DRY-RUN MODE - No actual deletions will be performed"))
    else:
        print(error_line("LIVE MODE - Resources will be permanently deleted!"))
    
    print(summary_item("Regions", "All regions" if all_regions else f"Selected: {', '.join(selected_regions)}"))
    
    if selected_services:
        print(summary_item("Regional Services", f"{len(selected_services)} services"))
    if selected_global_services:
        print(summary_item("Global Services", f"{len(selected_global_services)} services"))
    if rds_snapshot_prefix:
        print(summary_item("RDS Snapshots", f"Create with prefix '{rds_snapshot_prefix}'"))
    
    # Final confirmation
    if not dry_run:
        print(f"\n{error_line('WARNING: This will PERMANENTLY DELETE AWS resources!')}")
        confirm = inquirer.confirm("Are you absolutely sure you want to proceed?", default=False)
        if not confirm:
            print(f"\n{info_line('Operation cancelled by user. No changes made.')}")
            sys.exit(0)
    
    # Build arguments object
    class Args:
        def __init__(self):
            self.actually = not dry_run
            self.regions = selected_regions
            self.rds_final_snapshot_prefix = rds_snapshot_prefix
            self.services = None
            self.global_services = None
            self.resource_types = None
            self.all_regional = False
            self.all_global = False
            self.all_resources = False
            
            # Set the appropriate selection method
            if selection_type == "services":
                self.services = selected_services if selected_services else None
                self.global_services = selected_global_services if selected_global_services else None
            elif selection_type == "all-regional":
                self.all_regional = True
            elif selection_type == "all-global":
                self.all_global = True
            elif selection_type == "all-resources":
                self.all_resources = True
            else:
                # resource-types case - we already mapped to services above
                self.services = selected_services if selected_services else None
                self.global_services = selected_global_services if selected_global_services else None
    
    return Args()

def main():
    # Check if running in interactive mode (no arguments provided)
    if len(sys.argv) == 1:
        # No arguments provided, try to show interactive GUI
        args = show_interactive_menu()
        if args is None:
            # GUI not available, show help and exit
            print(info_line("Run with --help to see command-line options."))
            return
    else:
        # Parse command-line arguments
        parser = argparse.ArgumentParser(description="Dangerous account cleanup — DRY-RUN by default. Cleans ALL resources (regional + global) unless specific services are selected.")
        parser.add_argument("--really-delete", action="store_true", help="Actually perform deletions.")
        parser.add_argument("--regions", nargs="*", help="Limit to these regions (default: all).")
        parser.add_argument("--rds-final-snapshot-prefix", help="If set, create final RDS snapshots with this prefix (else SkipFinalSnapshot=True).")
        parser.add_argument("--gui", action="store_true", help="Launch interactive GUI mode.")
        
        # Service selection arguments
        service_group = parser.add_mutually_exclusive_group()
        service_group.add_argument("--services", nargs="+", 
                                  choices=["autoscaling", "ec2", "lambda", "s3", "ecr", "logs", "cloudwatch", "acm", 
                                          "apigateway", "dynamodb", "sqs", "sns", "elbv2", "elb", "rds", "ecs", "eks", 
                                          "enis", "security-groups", "vpcs"],
                                  help="Select specific regional services to clean up")
        service_group.add_argument("--global-services", nargs="+",
                                  choices=["route53", "iam"],
                                  help="Select specific global services to clean up")
        service_group.add_argument("--resource-types", nargs="+",
                                  choices=["compute", "storage", "network", "database", "security", "containers", 
                                          "messaging", "api", "monitoring"],
                                  help="Select resource types to clean up")
        service_group.add_argument("--all-regional", action="store_true",
                                  help="Clean up all regional services only")
        service_group.add_argument("--all-global", action="store_true", 
                                  help="Clean up all global services only")
        service_group.add_argument("--all-resources", action="store_true",
                                  help="Clean up all regional and global services (same as default)")
        
        args = parser.parse_args()
        
        # Handle GUI mode from command line
        if args.gui:
            args = show_interactive_menu()
            if args is None:
                print(error_line("Interactive mode not available - Install with: pip install inquirer"))
                return
        
        # Convert argparse args to our Args object for consistency
        args.actually = args.really_delete

    acct = confirm_account()
    print(section_header("AWS CLEANUP CONFIGURATION"))

    # Get selected services
    regional_services, global_services = get_services_to_run(args)
    target_regions = args.regions or regions()
    
    # Clean summary display
    print(summary_item("Account ID", acct))
    print(summary_item("Target Regions", f"{len(target_regions)} regions"))
    if regional_services:
        print(summary_item("Regional Services", f"{len(regional_services)} services"))
    if global_services:
        print(summary_item("Global Services", f"{len(global_services)} services"))
    
    print()
    if not args.actually:
        print(info_line("DRY-RUN MODE - No actual deletions will be performed"))
    else:
        print(error_line("LIVE MODE - Resources will be permanently deleted!"))

    # Per-region cleanup (in parallel) - only if regional services selected
    if regional_services:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = [ex.submit(per_region_worker, r, args.actually, args.rds_final_snapshot_prefix, regional_services) for r in target_regions]
            for f in as_completed(futures):
                _ = f.result()

    # Global cleanup
    if "route53" in global_services:
        print(service_header("🌐 Route 53 DNS (Global)"))
        cleanup_route53(args.actually)

    if "iam" in global_services:
        print(service_header("🔐 IAM Resources (Global)"))
        cleanup_iam(args.actually)

    print(f"\n{success_line('All AWS cleanup operations completed! 🎉')}")

if __name__ == "__main__":
    main()