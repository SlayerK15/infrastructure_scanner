# src/providers/iam.py
import boto3
from typing import Dict, List
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

class IAMScanner:
    def __init__(self, session: boto3.Session, config: Dict):
        self.iam_client = session.client('iam')
        self.config = config

    def scan_iam_resources(self) -> List[Dict]:
        """Scan IAM users and roles for security issues."""
        issues = []
        issues.extend(self._scan_unused_users())
        issues.extend(self._scan_unused_roles())
        return issues

    def _scan_unused_users(self) -> List[Dict]:
        """Scan for unused IAM users."""
        issues = []
        try:
            users = self.iam_client.list_users()['Users']
            threshold_days = self.config['unused_iam_threshold_days']
            threshold_date = datetime.now(timezone.utc) - timedelta(days=threshold_days)

            for user in users:
                # Check last activity
                last_used = self._get_user_last_activity(user['UserName'])
                if last_used and last_used < threshold_date:
                    issues.append({
                        'type': 'unused_iam_user',
                        'resource_id': user['UserName'],
                        'severity': 'high',
                        'description': f"IAM user {user['UserName']} hasn't been used since {last_used.isoformat()}",
                        'remediation': 'Delete unused IAM user'
                    })

        except Exception as e:
            logger.error(f"Error scanning IAM users: {str(e)}")
        return issues

    def _scan_unused_roles(self) -> List[Dict]:
        """Scan for unused IAM roles."""
        issues = []
        try:
            roles = self.iam_client.list_roles()['Roles']
            threshold_days = self.config['unused_iam_threshold_days']
            threshold_date = datetime.now(timezone.utc) - timedelta(days=threshold_days)

            for role in roles:
                # Skip AWS service roles
                if self._is_service_role(role):
                    continue

                last_used = self._get_role_last_activity(role['RoleName'])
                if last_used and last_used < threshold_date:
                    issues.append({
                        'type': 'unused_iam_role',
                        'resource_id': role['RoleName'],
                        'severity': 'high',
                        'description': f"IAM role {role['RoleName']} hasn't been used since {last_used.isoformat()}",
                        'remediation': 'Delete unused IAM role'
                    })

        except Exception as e:
            logger.error(f"Error scanning IAM roles: {str(e)}")
        return issues

    def _get_user_last_activity(self, username: str) -> datetime:
        """Get last activity time for an IAM user."""
        try:
            response = self.iam_client.get_user(UserName=username)
            if 'PasswordLastUsed' in response['User']:
                return response['User']['PasswordLastUsed']

            # Check access keys
            keys = self.iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
            last_used = None
            for key in keys:
                key_usage = self.iam_client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                if 'LastUsedDate' in key_usage['AccessKeyLastUsed']:
                    key_last_used = key_usage['AccessKeyLastUsed']['LastUsedDate']
                    if not last_used or key_last_used > last_used:
                        last_used = key_last_used
            return last_used

        except Exception as e:
            logger.error(f"Error getting user activity: {str(e)}")
            return None

    def _get_role_last_activity(self, role_name: str) -> datetime:
        """Get last activity time for an IAM role."""
        try:
            response = self.iam_client.get_role(RoleName=role_name)
            return response['Role'].get('RoleLastUsed', {}).get('LastUsedDate')
        except Exception as e:
            logger.error(f"Error getting role activity: {str(e)}")
            return None

    def _is_service_role(self, role: Dict) -> bool:
        """Check if role is an AWS service role."""
        return role['Path'].startswith('/aws-service-role/')