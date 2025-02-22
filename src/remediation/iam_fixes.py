# src/remediation/iam_fixes.py
import boto3
from typing import Dict
import logging

logger = logging.getLogger(__name__)

class IAMRemediation:
    def __init__(self, session: boto3.Session):
        self.iam_client = session.client('iam')

    def delete_unused_user(self, username: str) -> Dict:
        """Delete an unused IAM user."""
        try:
            # Delete access keys
            keys = self.iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in keys:
                self.iam_client.delete_access_key(
                    UserName=username,
                    AccessKeyId=key['AccessKeyId']
                )

            # Delete user
            self.iam_client.delete_user(UserName=username)
            return {
                'status': 'success',
                'message': f'Successfully deleted user {username}'
            }
        except Exception as e:
            return {
                'status': 'failed',
                'message': str(e)
            }

    def delete_unused_role(self, role_name: str) -> Dict:
        """Delete an unused IAM role."""
        try:
            # Delete role policies
            attached_policies = self.iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached_policies['AttachedPolicies']:
                self.iam_client.detach_role_policy(
                    RoleName=role_name,
                    PolicyArn=policy['PolicyArn']
                )

            # Delete inline policies
            inline_policies = self.iam_client.list_role_policies(RoleName=role_name)
            for policy_name in inline_policies['PolicyNames']:
                self.iam_client.delete_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )

            # Delete role
            self.iam_client.delete_role(RoleName=role_name)
            return {
                'status': 'success',
                'message': f'Successfully deleted role {role_name}'
            }
        except Exception as e:
            return {
                'status': 'failed',
                'message': str(e)
            }