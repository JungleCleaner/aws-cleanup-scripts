# aws-cleanup-scripts

Open-source helper scripts for safely cleaning up AWS resources.

Each script handles the full deletion sequence for resources that require multiple API calls in a specific order, which would be error-prone to do manually. They are used by [Jungle Cleaner](https://junglecleaner.com) but work standalone with the AWS CLI.

## Scripts

| Script | Description |
|--------|-------------|
| [`delete-waf-classic-acl.sh`](delete-waf-classic-acl.sh) | Safely delete a WAF Classic Web ACL and all its associated rules |

## Usage

Each script supports `--dry-run` to preview the commands without executing them.

```bash
# Download a script
curl -fsSL https://raw.githubusercontent.com/JungleCleaner/aws-cleanup-scripts/main/<script>.sh -o <script>.sh

# Inspect what it will do
bash <script>.sh --help
bash <script>.sh [options] --dry-run

# Run for real
bash <script>.sh [options]
```

## Requirements

- AWS CLI v2
- `python3` (used for JSON parsing in some scripts)
- Appropriate IAM permissions for the resources being deleted

## Contributing

PRs welcome. Each script should:
- Support `--dry-run`
- Print each step clearly before executing it
- Be idempotent where possible
- Include a `--help` flag
