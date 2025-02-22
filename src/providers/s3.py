# src/providers/s3.py
import boto3
import logging

logger = logging.getLogger(__name__)

class S3Scanner:
    def __init__(self, config):
        self.config = config
        self.s3_client = boto3.client('s3', region_name=config['aws']['region'])
    
    def scan(self):
        issues = []
        try:
            buckets = self.s3_client.list_buckets()
            for bucket in buckets['Buckets']:
                bucket_name = bucket['Name']
                try:
                    encryption = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
                except self.s3_client.exceptions.ClientError:
                    issues.append({
                        'type': 's3',
                        'resource_id': bucket_name,
                        'severity': 'high',
                        'description': 'Bucket encryption is not enabled.',
                        'remediation': 'Enable encryption for the bucket.'
                    })
            logger.info(f"S3 Scan completed with {len(issues)} issues.")
        except Exception as e:
            logger.error(f"Error scanning S3: {str(e)}")
        return issues