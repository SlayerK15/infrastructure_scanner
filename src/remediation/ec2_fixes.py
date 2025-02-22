# src/remediation/ec2_fixes.py
import boto3
import logging

logger = logging.getLogger(__name__)

class EC2Remediator:
    def __init__(self):
        self.ec2_client = boto3.client('ec2')
    
    def remediate(self, issue):
        try:
            if issue['type'] == 'ec2':
                self.ec2_client.modify_instance_attribute(
                    InstanceId=issue['resource_id'],
                    NoPublicIpAddress=True
                )
                return {'status': 'success', 'message': 'Public IP removed'}
        except Exception as e:
            return {'status': 'failed', 'message': str(e)}