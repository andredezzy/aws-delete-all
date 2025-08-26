# AWS Cleanup Script

A comprehensive Python script to clean up AWS resources across multiple services and regions. **Runs in DRY-RUN mode by default** to prevent accidental deletions.

## ⚠️ DANGER WARNING

This script will **DELETE ALL RESOURCES** in the specified AWS account. Use with extreme caution and always test with DRY-RUN mode first.

## Features

### Regional Services (cleaned per region)
- **EC2**: Deletes Auto Scaling Groups (sets capacity to 0 first), terminates instances, deletes available EBS volumes, deregisters AMIs and their snapshots, deletes remaining snapshots, releases Elastic IPs, and removes key pairs
- **Lambda**: Deletes all functions
- **S3**: Empties and deletes buckets (handles both versioned and unversioned buckets, bucket-region aware)
- **ECR**: Force deletes repositories and their images
- **CloudWatch Logs**: Deletes all log groups
- **CloudWatch**: Deletes alarms, dashboards
- **ACM**: Deletes SSL/TLS certificates and their dependent resources (load balancers, CloudFront distributions, API Gateway domains)
- **API Gateway**: Deletes REST APIs, HTTP APIs, WebSocket APIs, and custom domains (both v1 and v2)
- **DynamoDB**: Deletes tables (removes deletion protection), global tables, and backups
- **SQS**: Deletes queues (standard and FIFO)
- **SNS**: Deletes topics and subscriptions
- **ENI**: Deletes available network interfaces
- **Security Groups**: Revokes all rules, removes cross-references, and deletes non-default security groups
- **Load Balancers**: Deletes ALB/NLB (ELBv2) and Classic ELB load balancers, plus target groups
- **VPC**: Comprehensive teardown including endpoints, NAT gateways, internet gateways (detach first), subnets, non-main route tables, non-default NACLs, peering connections, VPN attachments/gateways, then VPCs
- **RDS**: Deletes DB clusters and instances (removes deletion protection), snapshots, and subnet groups
- **ECS**: Deletes services, clusters, and capacity providers (excludes AWS-managed Fargate providers)
- **EKS**: Deletes add-ons, Fargate profiles, nodegroups, and clusters; attempts to remove IAM OIDC providers

### Global Services (opt-in)
- **Route 53**: Disables DNSSEC, deletes all record sets (except apex NS/SOA), disassociates VPCs from private zones, and deletes hosted zones
- **IAM**: Deletes identity providers (OIDC/SAML, excludes those with "aws" or "DO_NOT_DELETE" in name), deletes roles (excludes those starting with "AWS"), deletes instance profiles, detaches and deletes customer-managed policies (excludes AWS-managed policies)

## Prerequisites

- Python 3.6+
- AWS CLI configured with appropriate credentials
- Required Python packages:
  ```bash
  pip install boto3
  ```

## AWS Permissions

The script requires extensive AWS permissions. Consider using a policy with the following actions:
- `ec2:*` (instances, volumes, AMIs, snapshots, Elastic IPs, key pairs, ENIs, security groups, VPCs)
- `autoscaling:*` (Auto Scaling Groups)
- `s3:*` (buckets and objects)
- `ecr:*` (repositories)
- `lambda:*` (functions)
- `logs:*` (log groups)
- `acm:*` (SSL/TLS certificates)
- `cloudfront:*` (CloudFront distributions using certificates)
- `apigateway:*` (API Gateway REST APIs, custom domains)
- `apigatewayv2:*` (API Gateway HTTP/WebSocket APIs, custom domains)
- `dynamodb:*` (DynamoDB tables, backups)
- `sqs:*` (SQS queues)
- `sns:*` (SNS topics, subscriptions)
- `cloudwatch:*` (CloudWatch alarms, dashboards)
- `ecs:*` (ECS clusters, services, capacity providers)
- `elbv2:*` (Application/Network Load Balancers, target groups)
- `elasticloadbalancing:*` (Classic Load Balancers)
- `rds:*` (DB instances, clusters, snapshots, subnet groups)
- `eks:*` (clusters, nodegroups, Fargate profiles, add-ons)
- `iam:ListOpenIDConnectProviders`, `iam:GetOpenIDConnectProvider`, `iam:DeleteOpenIDConnectProvider`, `iam:ListSAMLProviders`, `iam:DeleteSAMLProvider`, `iam:ListRoles`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:ListInstanceProfilesForRole`, `iam:DetachRolePolicy`, `iam:DeleteRolePolicy`, `iam:RemoveRoleFromInstanceProfile`, `iam:DeleteRole`, `iam:ListInstanceProfiles`, `iam:DeleteInstanceProfile`, `iam:ListPolicies`, `iam:ListEntitiesForPolicy`, `iam:DetachUserPolicy`, `iam:DetachGroupPolicy`, `iam:ListPolicyVersions`, `iam:DeletePolicyVersion`, `iam:DeletePolicy` (for IAM cleanup)
- `route53:*` (if using `--include-route53`)
- `sts:GetCallerIdentity`

## Installation

### Method 1: Using Virtual Environment (Recommended)

1. Clone or download the script:
   ```bash
   git clone <repository-url>
   cd aws-delete-all
   ```

2. Create and activate a virtual environment:
   ```bash
   # Create virtual environment
   python3 -m venv venv
   
   # Activate virtual environment
   # On macOS/Linux:
   source venv/bin/activate
   
   # On Windows:
   venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   # Install all dependencies from requirements.txt (recommended)
   pip install -r requirements.txt
   
   # Or install manually:
   # pip install boto3 inquirer
   ```
   
   **Note:** The `requirements.txt` file includes both core dependencies (`boto3`) and optional GUI dependencies (`inquirer`).

4. Configure AWS credentials (see AWS Configuration section below)

### Method 2: Global Installation

1. Clone or download the script
2. Install dependencies globally:
   ```bash
   # Install all dependencies from requirements.txt (recommended)
   pip install -r requirements.txt
   
   # Or install manually:
   # pip install boto3 inquirer
   ```
   
   **Note:** The `requirements.txt` file includes both core dependencies (`boto3`) and optional GUI dependencies (`inquirer`).

### AWS Configuration

Configure AWS credentials using one of these methods:
- **AWS CLI**: `aws configure`
- **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- **IAM roles** (if running on EC2)
- **AWS profiles**: `export AWS_PROFILE=your-profile`

### Virtual Environment Management

```bash
# Activate virtual environment (when returning to project)
source venv/bin/activate  # macOS/Linux
# or
venv\Scripts\activate     # Windows

# Deactivate virtual environment (when done)
deactivate

# Remove virtual environment (if needed)
rm -rf venv  # macOS/Linux
# or
rmdir /s venv  # Windows
```

## Usage

### 🚀 Quick Start

**New to this tool? Start here:**

1. **Safe exploration** (recommended first step):
   ```bash
   python aws_cleanup.py
   ```
   - Launches interactive GUI
   - Shows what would be deleted (DRY-RUN mode)
   - No actual changes made to your AWS account

2. **Ready to clean up?** Re-run and choose "actual deletion" when prompted

3. **Command-line user?** Use `python aws_cleanup.py` for DRY-RUN

### 🎯 Interactive GUI Mode (Recommended)

The easiest way to use this tool is through the interactive GUI mode:

```bash
python aws_cleanup.py
```

**Features:**
- 🎮 **Arrow key navigation** - Navigate menus intuitively
- ☑️ **Checkbox selection** - Multi-select services with spacebar
- 🛡️ **Safety first** - DRY-RUN mode is default and highlighted
- 📋 **Guided workflow** - Step-by-step prompts for all options
- 👀 **Visual confirmation** - Clear summary before any action
- 🔰 **Beginner-friendly** - No command-line knowledge required

**Interactive Workflow:**
1. **Selection Method** → Choose how to select services (specific services, resource types, or bulk options)
2. **Service Selection** → Multi-select from organized lists with descriptions
3. **Global Services** → Optionally include Route 53 DNS and IAM resources
4. **Safety Mode** → Choose DRY-RUN (recommended) or actual deletion
5. **Regions** → Select all regions or specific ones
6. **RDS Options** → Configure final snapshots if RDS is selected
7. **Confirmation** → Review summary and confirm before execution

**Alternative launch:**
```bash
python aws_cleanup.py --gui
```

**Requirements:** Requires `inquirer` library. If not installed, falls back to command-line help.

### 💻 Command-Line Mode

For automation, scripting, or advanced users who prefer command-line interfaces:

**Basic Usage:**
```bash
# DRY-RUN mode (shows what would be deleted, safe to run)
python aws_cleanup.py

# DRY-RUN for specific regions
python aws_cleanup.py --regions us-east-1 us-west-2

# ACTUAL DELETION (⚠️ DANGEROUS!) - deletes ALL resources by default
python aws_cleanup.py --really-delete
```

**RDS Snapshot Control:**
```bash
# Skip final snapshots (faster, default)
python aws_cleanup.py --really-delete

# Create final snapshots before deletion
python aws_cleanup.py --really-delete --rds-final-snapshot-prefix backup-$(date +%s)
```

### 🎯 Selective Service Cleanup

**By Specific Services:**
```bash
# Clean specific regional services
python aws_cleanup.py --services ec2 s3 rds dynamodb

# Clean specific global services  
python aws_cleanup.py --global-services route53 iam

# Combine regional and global
python aws_cleanup.py --services ec2 s3 --global-services iam
```

**By Resource Types:**
```bash
# Clean compute resources (ASG, EC2, Lambda)
python aws_cleanup.py --resource-types compute

# Clean storage resources (S3, ECR, DynamoDB)
python aws_cleanup.py --resource-types storage

# Clean multiple types
python aws_cleanup.py --resource-types compute storage network

# All available types: compute, storage, network, database, security, containers, messaging, api, monitoring
```

**Bulk Operations:**
```bash
# All regional services only (excludes Route 53 & IAM)
python aws_cleanup.py --all-regional

# All global services only (Route 53 & IAM)
python aws_cleanup.py --all-global  

# Everything explicitly (same as default behavior)
python aws_cleanup.py --all-resources

# Note: Running without service selection defaults to ALL resources (regional + global)
```

**Advanced Combinations:**
```bash
# Specific services in specific regions with snapshots
python aws_cleanup.py --services rds dynamodb --regions us-east-1 us-west-2 --rds-final-snapshot-prefix backup-$(date +%s)

# Actual deletion of compute resources in production regions
python aws_cleanup.py --resource-types compute --regions us-east-1 eu-west-1 --really-delete
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--gui` | Launch interactive GUI mode with arrow key navigation |
| `--really-delete` | Actually perform deletions (otherwise runs in DRY-RUN mode) |
| `--regions` | Specify regions to clean (default: all available regions) |
| `--rds-final-snapshot-prefix` | Create final RDS snapshots with this prefix (default: skip final snapshots) |

### Service Selection Options (Mutually Exclusive)

| Option | Description |
|--------|-------------|
| `--services` | Select specific regional services: `autoscaling`, `ec2`, `lambda`, `s3`, `ecr`, `logs`, `cloudwatch`, `acm`, `apigateway`, `dynamodb`, `sqs`, `sns`, `elbv2`, `elb`, `rds`, `ecs`, `eks`, `enis`, `security-groups`, `vpcs` |
| `--global-services` | Select specific global services: `route53`, `iam` |
| `--resource-types` | Select by resource type: `compute`, `storage`, `network`, `database`, `security`, `containers`, `messaging`, `api`, `monitoring` |
| `--all-regional` | Clean up all regional services (default behavior) |
| `--all-global` | Clean up all global services |
| `--all-resources` | Clean up all regional and global services |

### Resource Type Mappings

| Resource Type | Included Services |
|---------------|-------------------|
| `compute` | Auto Scaling Groups, EC2 instances, Lambda functions |
| `storage` | S3 buckets, ECR repositories, DynamoDB tables |
| `network` | Load balancers (ALB/NLB/Classic), ENIs, Security Groups, VPCs |
| `database` | RDS instances and clusters, DynamoDB tables |
| `security` | IAM (global service) |
| `containers` | ECS clusters, EKS clusters, ECR repositories |
| `messaging` | SQS queues, SNS topics |
| `api` | API Gateway (REST/HTTP/WebSocket APIs) |
| `monitoring` | CloudWatch Logs, CloudWatch alarms/dashboards |

### Environment Variables

```bash
# Avoid pager interaction
export AWS_PAGER=""

# Use specific AWS profile
export AWS_PROFILE=cleanup-profile

# Set AWS credentials (alternative to AWS CLI config)
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
```

## Examples

### Safe Testing
```bash
# Test what would be deleted in your account
python aws_cleanup.py

# Test specific regions
python aws_cleanup.py --regions us-east-1 eu-west-1

# Test with Route 53 included
python aws_cleanup.py --include-route53
```

### Actual Cleanup (Destructive)
```bash
# Clean up everything except Route 53
python aws_cleanup.py --really-delete

# Clean up specific regions including Route 53
python aws_cleanup.py --really-delete --regions us-east-1 --include-route53

# Full account cleanup with RDS final snapshots (NUCLEAR OPTION)
python aws_cleanup.py --really-delete --include-route53 --include-iam --rds-final-snapshot-prefix backup-$(date +%s)

# Full account cleanup without final snapshots (NUCLEAR OPTION)
python aws_cleanup.py --really-delete --include-route53 --include-iam
```

## How It Works

1. **Account Verification**: Confirms the AWS account ID before proceeding
2. **Region Discovery**: Automatically discovers all available AWS regions (unless specified)
3. **Parallel Processing**: Uses ThreadPoolExecutor to clean multiple regions simultaneously
4. **Order-Aware Cleanup**: Follows proper dependency order (compute → containers → storage → load balancers → databases → network → VPCs)
5. **Error Handling**: Continues processing even if individual operations fail
6. **Safe Defaults**: Always runs in DRY-RUN mode unless explicitly told to delete
7. **Resource Dependencies**: Handles complex dependencies (e.g., EKS OIDC providers, VPC teardown sequence)

## Output Format

The script provides clear output indicating:
- `[DRY-RUN]` prefix for simulated operations
- Resource type and identifier being processed
- Region information for regional resources
- Error messages for failed operations

Example output:
```
Account: 123456789012
Regions: us-east-1, us-west-2, eu-west-1
MODE: DRY-RUN (no delete calls will be made)

=== Region: us-east-1 ===
[DRY-RUN] Auto Scaling Group cleanup: us-east-1 my-asg
[DRY-RUN] Set ASG desired capacity to 0: us-east-1 my-asg
[DRY-RUN] Delete Auto Scaling Group: us-east-1 my-asg
[DRY-RUN] Terminate EC2 instances: us-east-1 ['i-1234567890abcdef0']
[DRY-RUN] Delete EBS volume: us-east-1 vol-0123456789abcdef0
[DRY-RUN] Delete Lambda function: us-east-1 my-function
[DRY-RUN] Empty + delete S3 bucket: us-east-1 s3://my-test-bucket
[DRY-RUN] Delete ECR repository (force): us-east-1 my-repo
[DRY-RUN] ACM Certificate in use, deleting dependent resources: us-east-1 example.com (used by 2 resources)
[DRY-RUN] Delete Load Balancer (using certificate): us-east-1 arn:aws:elasticloadbalancing:us-east-1:...
[DRY-RUN] Delete API Gateway Domain Name (using certificate): us-east-1 api.example.com
[DRY-RUN] Delete ACM Certificate: us-east-1 example.com (arn:aws:acm:us-east-1:123456789012:certificate/...)
[DRY-RUN] Delete ACM Certificate: us-east-1 old-domain.com (arn:aws:acm:us-east-1:123456789012:certificate/...)
[DRY-RUN] EKS Cluster cleanup: us-east-1 my-cluster
[DRY-RUN] Delete EKS Nodegroup: us-east-1 my-cluster/my-nodegroup
[DRY-RUN] Delete EKS Cluster: us-east-1 my-cluster
[DRY-RUN] Delete ELBv2: us-east-1 arn:aws:elasticloadbalancing:us-east-1:...
[DRY-RUN] RDS Instance: disable deletion protection: us-east-1 my-db-instance
[DRY-RUN] Delete RDS Instance: us-east-1 my-db-instance
[DRY-RUN] Delete ENI: us-east-1 eni-12345678
[DRY-RUN] Revoke SG ingress: sg-12345678 (2 rules)
[DRY-RUN] Delete Security Group: us-east-1 sg-12345678
[DRY-RUN] VPC teardown (best-effort): us-east-1 vpc-12345678

=== Global: IAM ===
[DRY-RUN] Delete OIDC Identity Provider: my-oidc-provider (arn:aws:iam::123456789012:oidc-provider/my-oidc-provider)
[DRY-RUN] Skip SAML Provider (protected): aws-sso-provider (arn:aws:iam::123456789012:saml-provider/aws-sso-provider)
[DRY-RUN] Skip IAM Role (AWS service role): AWSServiceRoleForECS
[DRY-RUN] IAM Role cleanup: MyCustomRole
[DRY-RUN] Detach managed policy from role: AmazonS3ReadOnlyAccess from MyCustomRole
[DRY-RUN] Delete inline policy from role: MyInlinePolicy from MyCustomRole
[DRY-RUN] Remove role from instance profile: MyCustomRole from MyInstanceProfile
[DRY-RUN] Delete IAM Role: MyCustomRole
[DRY-RUN] IAM Instance Profile cleanup: MyInstanceProfile
[DRY-RUN] Remove role from instance profile: MyCustomRole from MyInstanceProfile
[DRY-RUN] Delete IAM Instance Profile: MyInstanceProfile
[DRY-RUN] IAM Policy cleanup: MyCustomPolicy (arn:aws:iam::123456789012:policy/MyCustomPolicy)
[DRY-RUN] Detach policy from role: MyCustomPolicy from MyRole
[DRY-RUN] Delete IAM Policy: MyCustomPolicy (arn:aws:iam::123456789012:policy/MyCustomPolicy)
```

## Configuration

The script includes several configurable parameters at the top:

```python
CFG = Config(retries={"max_attempts": 10, "mode": "standard"})
MAX_WORKERS = 16
```

- **Retries**: Configured for up to 10 retry attempts with standard backoff
- **Max Workers**: Limits concurrent region processing to 16 threads

## Safety Features

1. **DRY-RUN Default**: Never deletes unless explicitly requested
2. **Account Confirmation**: Shows which AWS account will be affected
3. **Detailed Logging**: Shows exactly what resources will be/were processed
4. **Error Resilience**: Individual failures don't stop the entire process
5. **Resource-Aware**: Handles complex dependencies and proper deletion order
6. **RDS Protection**: Removes deletion protection automatically before cleanup
7. **VPC Teardown**: Systematic teardown of VPC components in correct order
8. **Security Group Cleanup**: Removes cross-references between security groups

## Troubleshooting

### Common Issues

1. **Permission Errors**: Ensure your AWS credentials have sufficient permissions for all services
2. **Region Access**: Some regions may require explicit opt-in
3. **Resource Dependencies**: Complex dependencies are handled automatically, but some edge cases may require manual intervention
4. **Rate Limiting**: The script includes retry logic for AWS API rate limits
5. **EKS Cleanup**: Nodegroups and Fargate profiles must be deleted before clusters
6. **RDS Deletion Protection**: The script automatically disables deletion protection
7. **VPC Dependencies**: Load balancers, ENIs, and security groups are cleaned before VPC teardown

### Best Practices

1. **Always test first**: Run without `--really-delete` to see what would be affected
2. **Use specific regions**: Limit scope with `--regions` for targeted cleanup
3. **Consider RDS snapshots**: Use `--rds-final-snapshot-prefix` to create final backups before deletion
4. **Check billing**: Monitor AWS billing after cleanup to ensure resources are properly deleted
5. **Backup important data**: Ensure you have backups of any data you want to keep
6. **Review EKS resources**: EKS cleanup includes OIDC provider removal which affects cluster authentication
7. **VPC cleanup order**: The script handles VPC teardown systematically, but complex custom setups may need manual review

## License

This script is provided as-is for educational and cleanup purposes. Use at your own risk.

## Contributing

Feel free to submit issues or pull requests to improve the script's functionality or add support for additional AWS services.
