# AWS Infrastructure Security Scanner

An automated tool for scanning AWS infrastructure, detecting security issues, and performing auto-remediation.

## Features

- Multi-region AWS resource scanning
- Detects security issues across multiple services:
  - EC2 (public IPs, missing tags, unused instances)
  - S3 (unencrypted buckets, public access)
  - IAM (unused users and roles)
- Automatic remediation of security issues
- Email notifications for scan results
- Detailed JSON reports
- GitHub Actions integration for automated scanning

## Prerequisites

- Python 3.9 or higher
- AWS Account with appropriate permissions
- GitHub repository (for GitHub Actions)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/SlayerK15/infrastructure_scanner.git
cd infrastructure_scanner
```

2. Install the package:
```bash
pip install -e .
```

## Configuration

### Required Secrets

The following secrets need to be configured:

1. AWS Credentials:
   - `AWS_ACCESS_KEY_ID`: Your AWS access key
   - `AWS_SECRET_ACCESS_KEY`: Your AWS secret key
   - Required permissions:
     - EC2: DescribeInstances, ModifyInstanceAttribute
     - S3: ListBuckets, GetBucketEncryption, PutBucketEncryption, GetPublicAccessBlock, PutPublicAccessBlock
     - IAM: ListUsers, ListRoles, GetUser, GetRole, DeleteUser, DeleteRole

2. Email Notifications:
   - `EMAIL_USERNAME`: Email username for notifications
   - `EMAIL_APP_PASSWORD`: App password for email account
   - `EMAIL_FROM`: Sender email address
   - `EMAIL_TO`: Recipient email address

### Setting up Secrets

#### For Local Development
Create a `.env` file in the project root:
```env
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
EMAIL_APP_PASSWORD=your_email_app_password
EMAIL_USERNAME=your_email
EMAIL_FROM=sender@email.com
EMAIL_TO=recipient@email.com
```

#### For GitHub Actions
1. Go to your GitHub repository
2. Navigate to Settings > Secrets and variables > Actions
3. Add the following repository secrets:
   - AWS_ACCESS_KEY_ID
   - AWS_SECRET_ACCESS_KEY
   - EMAIL_APP_PASSWORD
   - EMAIL_USERNAME
   - EMAIL_FROM
   - EMAIL_TO

## Usage

### Local Execution

Run the scanner:
```bash
python -m src.scanner
```

### GitHub Actions

The scanner will run automatically:
- Daily at midnight (configured in workflow)
- Manually via the Actions tab in GitHub

## Reports

Reports are generated in the `reports/` directory with the format:
```json
{
  "timestamp": "...",
  "issues": [...],
  "remediation_results": [...]
}
```

## Auto-Remediation

The scanner can automatically fix the following issues:
- Public EC2 instances
- Unencrypted S3 buckets
- Public S3 bucket access
- Unused IAM users
- Unused IAM roles (except AWS service roles)

Configure auto-remediation in `config/config.yaml`:
```yaml
auto_remediate_types:
  - unencrypted_bucket
  - public_access_possible
  - unused_instance
  - unused_iam_user
  - unused_iam_role

auto_remediate_severities:
  - high
  - medium
```

## Safety Notes

- AWS service roles (prefixed with 'AWSServiceRole') are automatically skipped during remediation
- Email notifications include only high-severity issues in the summary
- All remediation actions are logged and reported

## License

MIT License
