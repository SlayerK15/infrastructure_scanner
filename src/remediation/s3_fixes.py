# src/remediation/s3_fixes.py
import boto3
import logging

logger = logging.getLogger(__name__)

class S3Remediator:
    def __init__(self, session=None):
        if session:
            self.s3_client = session.client('s3')
        else:
            # Fallback to default session with region
            self.s3_client = boto3.client('s3', region_name='us-east-1')
    
    def remediate(self, issue):
        try:
            if issue['type'] == 'unencrypted_bucket':
                return self._enable_encryption(issue['resource_id'])
            elif issue['type'] == 'public_access_possible':
                return self._block_public_access(issue['resource_id'])
            return {'status': 'skipped', 'message': f"Unsupported issue type: {issue['type']}"}
            
        except Exception as e:
            error_msg = f"Error remediating {issue['type']} {issue['resource_id']}: {str(e)}"
            logger.error(error_msg)
            return {'status': 'failed', 'message': error_msg}

    def _enable_encryption(self, bucket_name):
        """Enable default encryption for a bucket"""
        try:
            self.s3_client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                        {'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}
                    ]
                }
            )
            return {'status': 'success', 'message': 'Encryption enabled'}
        except Exception as e:
            return {'status': 'failed', 'message': str(e)}
    
    def _block_public_access(self, bucket_name):
        """Block all public access for a bucket"""
        try:
            self.s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            return {'status': 'success', 'message': 'Public access blocked'}
        except Exception as e:
            return {'status': 'failed', 'message': str(e)}