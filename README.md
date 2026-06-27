# aws-cleanup-scripts

Open-source helper scripts for safely cleaning up AWS resources.

Each script handles the full deletion sequence for resources that require multiple API calls in a specific order, which would be error-prone to do manually. They are used by [Jungle Cleaner](https://junglecleaner.com) but work standalone with the AWS CLI.

## Scripts

| Script | Description |
|--------|-------------|
| [`delete-waf-classic-acl.py`](delete-waf-classic-acl.py) | Delete a WAF Classic Web ACL and all its associated rules in the correct order |
| [`delete-route53-hosted-zone.py`](delete-route53-hosted-zone.py) | Delete a Route53 hosted zone and all its records |

## Usage

Each script supports `--dry-run` to preview what it will do without making any changes.

```bash
# Download a script
curl -fsSL https://raw.githubusercontent.com/JungleCleaner/aws-cleanup-scripts/main/<script>.py -o <script>.py

# Inspect what it will do
python3 <script>.py --help
python3 <script>.py [options] --dry-run

# Run for real
python3 <script>.py [options]
```

## Requirements

- Python 3.7+
- [boto3](https://pypi.org/project/boto3/) — `pip install boto3`
- Appropriate IAM permissions for the resources being deleted

Works on macOS, Linux, and Windows.

## Contributing

PRs welcome. Each script should:
- Support `--dry-run`
- Print each step clearly before executing it
- Be idempotent where possible
- Include `--help`
