# src/scanner.py
import boto3
import logging
from datetime import datetime, timezone, timedelta
import json
import os
from typing import List, Dict
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from .remediation.ec2_fixes import EC2Remediator
from .remediation.s3_fixes import S3Remediator
from .remediation.iam_fixes import IAMRemediation

# Load environment variables
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AWSScanner:
    def __init__(self, config_path: str):
        """Initialize AWS Scanner"""
        self.config = self._load_config(config_path)
        self.sessions = self._create_sessions()
        self.remediators = self._initialize_remediators()

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from file"""
        import yaml
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            # Load credentials from .env
            if config['aws'].get('use_env_file'):
                config['aws']['access_key_id'] = os.getenv('AWS_ACCESS_KEY_ID')
                config['aws']['secret_access_key'] = os.getenv('AWS_SECRET_ACCESS_KEY')
            return config

    def _create_sessions(self) -> Dict[str, boto3.Session]:
        """Create AWS sessions for each region"""
        sessions = {}
        for region in self.config['aws']['regions']:
            sessions[region] = boto3.Session(
                aws_access_key_id=self.config['aws']['access_key_id'],
                aws_secret_access_key=self.config['aws']['secret_access_key'],
                region_name=region
            )
        return sessions

    def _initialize_remediators(self) -> Dict:
        """Initialize remediation classes for each region"""
        remediators = {}
        for region in self.config['aws']['regions']:
            session = self.sessions[region]
            remediators[region] = {
                'ec2': EC2Remediator(),
                's3': S3Remediator(),
                'iam': IAMRemediation(session)
            }
        return remediators

    def scan(self) -> List[Dict]:
        """Perform security scan across all regions"""
        all_issues = []
        for region, session in self.sessions.items():
            logger.info(f"Scanning region: {region}")
            try:
                ec2_issues = self._scan_ec2(session, region)
                s3_issues = self._scan_s3(session, region)
                all_issues.extend(ec2_issues + s3_issues)
            except Exception as e:
                logger.error(f"Error scanning {region}: {str(e)}")

        # IAM is global, scan once
        try:
            iam_issues = self._scan_iam(next(iter(self.sessions.values())))
            all_issues.extend(iam_issues)
        except Exception as e:
            logger.error(f"Error scanning IAM: {str(e)}")

        return all_issues

    def _scan_ec2(self, session: boto3.Session, region: str) -> List[Dict]:
        """Scan EC2 instances in a region"""
        issues = []
        ec2_client = session.client('ec2')
        cloudwatch = session.client('cloudwatch')

        try:
            instances = ec2_client.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    # Check public IP
                    if 'PublicIpAddress' in instance:
                        issues.append({
                            'type': 'public_instance',
                            'resource_id': instance['InstanceId'],
                            'region': region,
                            'severity': 'high',
                            'description': f"Instance has public IP: {instance['PublicIpAddress']}"
                        })

                    # Check tags
                    instance_tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    missing_tags = set(self.config['required_tags']) - set(instance_tags.keys())
                    if missing_tags:
                        issues.append({
                            'type': 'missing_tags',
                            'resource_id': instance['InstanceId'],
                            'region': region,
                            'severity': 'medium',
                            'description': f"Missing required tags: {', '.join(missing_tags)}"
                        })

                    # Check usage
                    if self._is_instance_unused(cloudwatch, instance['InstanceId']):
                        issues.append({
                            'type': 'unused_instance',
                            'resource_id': instance['InstanceId'],
                            'region': region,
                            'severity': 'medium',
                            'description': "Instance appears unused"
                        })

        except Exception as e:
            logger.error(f"EC2 scan error in {region}: {str(e)}")

        return issues

    def _is_instance_unused(self, cloudwatch, instance_id: str) -> bool:
        """Check if EC2 instance is unused based on CPU utilization"""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=self.config['unused_resource_threshold_days'])
        
        response = cloudwatch.get_metric_statistics(
            Namespace='AWS/EC2',
            MetricName='CPUUtilization',
            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,
            Statistics=['Average']
        )

        # Check if CPU usage is consistently below threshold
        return all(
            datapoint['Average'] < self.config['unused_cpu_threshold']
            for datapoint in response['Datapoints']
        )

    def _scan_s3(self, session: boto3.Session, region: str) -> List[Dict]:
        """Scan S3 buckets in a region"""
        issues = []
        s3_client = session.client('s3')

        try:
            buckets = s3_client.list_buckets()['Buckets']
            for bucket in buckets:
                try:
                    # Check encryption
                    try:
                        s3_client.get_bucket_encryption(Bucket=bucket['Name'])
                    except s3_client.exceptions.ClientError:
                        issues.append({
                            'type': 'unencrypted_bucket',
                            'resource_id': bucket['Name'],
                            'region': region,
                            'severity': 'high',
                            'description': 'Bucket is not encrypted'
                        })

                    # Check public access
                    public_access = s3_client.get_public_access_block(Bucket=bucket['Name'])
                    if not all(public_access['PublicAccessBlockConfiguration'].values()):
                        issues.append({
                            'type': 'public_access_possible',
                            'resource_id': bucket['Name'],
                            'region': region,
                            'severity': 'high',
                            'description': 'Bucket public access is not fully blocked'
                        })

                except Exception as e:
                    logger.error(f"Error checking bucket {bucket['Name']}: {str(e)}")

        except Exception as e:
            logger.error(f"S3 scan error in {region}: {str(e)}")

        return issues

    def _scan_iam(self, session: boto3.Session) -> List[Dict]:
        """Scan IAM users and roles"""
        issues = []
        iam_client = session.client('iam')
        threshold_date = datetime.now(timezone.utc) - timedelta(days=self.config['unused_iam_threshold_days'])

        try:
            # Check IAM users
            users = iam_client.list_users()['Users']
            for user in users:
                if 'PasswordLastUsed' in user and user['PasswordLastUsed'] < threshold_date:
                    issues.append({
                        'type': 'unused_iam_user',
                        'resource_id': user['UserName'],
                        'region': 'global',
                        'severity': 'high',
                        'description': f"IAM user hasn't logged in since {user['PasswordLastUsed'].isoformat()}"
                    })

            # Check IAM roles
            roles = iam_client.list_roles()['Roles']
            for role in roles:
                if not role['RoleName'].startswith('aws-service-role'):
                    role_last_used = iam_client.get_role(RoleName=role['RoleName'])['Role'].get('RoleLastUsed', {})
                    if 'LastUsedDate' in role_last_used and role_last_used['LastUsedDate'] < threshold_date:
                        issues.append({
                            'type': 'unused_iam_role',
                            'resource_id': role['RoleName'],
                            'region': 'global',
                            'severity': 'medium',
                            'description': f"IAM role not used since {role_last_used['LastUsedDate'].isoformat()}"
                        })

        except Exception as e:
            logger.error(f"IAM scan error: {str(e)}")

        return issues

    def _should_auto_remediate(self, issue: Dict) -> bool:
        """Check if an issue should be auto-remediated based on config"""
        return (
            issue['type'] in self.config['auto_remediate_types'] and
            issue['severity'] in self.config['auto_remediate_severities']
        )

    def _remediate_issue(self, issue: Dict, region: str) -> Dict:
        """Attempt to remediate a single issue"""
        try:
            remediator = self.remediators[region]
            result = {'status': 'skipped', 'message': 'No remediation available'}

            if issue['type'] == 'public_instance':
                result = remediator['ec2'].remediate(issue)
            elif issue['type'] in ['unencrypted_bucket', 'public_access_possible']:
                result = remediator['s3'].remediate(issue)
            elif issue['type'] == 'unused_iam_user':
                result = remediator['iam'].delete_unused_user(issue['resource_id'])
            elif issue['type'] == 'unused_iam_role' and not issue['resource_id'].startswith('AWSServiceRole'):
                result = remediator['iam'].delete_unused_role(issue['resource_id'])

            logger.info(f"Remediation for {issue['type']} {issue['resource_id']}: {result['status']}")
            return result

        except Exception as e:
            error_msg = f"Error remediating {issue['type']} {issue['resource_id']}: {str(e)}"
            logger.error(error_msg)
            return {'status': 'failed', 'message': error_msg}

    def _auto_remediate(self, issues: List[Dict]) -> List[Dict]:
        """Attempt to auto-remediate eligible issues"""
        remediation_results = []
        
        for issue in issues:
            if self._should_auto_remediate(issue):
                region = issue.get('region', 'us-east-1')  # Default to us-east-1 if region not specified
                if issue['region'] == 'global':
                    region = self.config['aws']['regions'][0]  # Use first region for global services
                
                result = self._remediate_issue(issue, region)
                remediation_results.append({
                    'issue': issue,
                    'remediation_result': result
                })

        return remediation_results

    def _send_notifications(self, report: Dict):
        """Send email notification"""
        if self.config['notifications']['email']['enabled']:
            try:
                msg = MIMEMultipart()
                msg['Subject'] = f"AWS Security Scan Report - {datetime.now().strftime('%Y-%m-%d')}"
                msg['From'] = self.config['notifications']['email']['from_address']
                msg['To'] = self.config['notifications']['email']['to_address']

                # Create report summary
                summary = f"""
                AWS Security Scan Summary:
                Total Issues: {len(report['issues'])}
                High Severity: {len([i for i in report['issues'] if i['severity'] == 'high'])}
                Medium Severity: {len([i for i in report['issues'] if i['severity'] == 'medium'])}
                Low Severity: {len([i for i in report['issues'] if i['severity'] == 'low'])}

                Critical Issues:
                """

                critical_issues = [i for i in report['issues'] if i['severity'] == 'high']
                for issue in critical_issues[:5]:  # Show top 5 critical issues
                    summary += f"- {issue['type']}: {issue['description']}\n"

                # Add remediation summary if available
                if 'remediation_results' in report:
                    successful_remediations = len([r for r in report['remediation_results'] 
                                                 if r['remediation_result']['status'] == 'success'])
                    failed_remediations = len([r for r in report['remediation_results'] 
                                             if r['remediation_result']['status'] == 'failed'])
                    
                    summary += f"\nRemediation Summary:"
                    summary += f"\nSuccessful Remediations: {successful_remediations}"
                    summary += f"\nFailed Remediations: {failed_remediations}\n"

                msg.attach(MIMEText(summary, 'plain'))

                # Send email
                with smtplib.SMTP(self.config['notifications']['email']['smtp_server'], 
                                self.config['notifications']['email']['smtp_port']) as server:
                    server.starttls()
                    server.login(
                        self.config['notifications']['email']['username'],
                        os.getenv('EMAIL_APP_PASSWORD')
                    )
                    server.send_message(msg)

            except Exception as e:
                logger.error(f"Error sending email notification: {str(e)}")

    def run(self):
        """Execute the scanner and auto-remediation"""
        try:
            logger.info("Starting security scan...")
            issues = self.scan()
            
            # Perform auto-remediation
            logger.info("Starting auto-remediation...")
            remediation_results = self._auto_remediate(issues)
            
            report = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'issues': issues,
                'remediation_results': remediation_results
            }
            
            # Send notifications
            self._send_notifications(report)
            
            # Save report
            os.makedirs('reports', exist_ok=True)
            filename = f"reports/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
                
            logger.info(f"Scan and remediation complete. Report saved to {filename}")
            return report
            
        except Exception as e:
            logger.error(f"Scanner error: {str(e)}")
            raise

if __name__ == '__main__':
    scanner = AWSScanner('config/config.yaml')
    scanner.run()