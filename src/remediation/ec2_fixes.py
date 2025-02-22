# src/remediation/ec2_fixes.py
import boto3
import logging

logger = logging.getLogger(__name__)

class EC2Remediator:
    def __init__(self, session=None):
        if session:
            self.ec2_client = session.client('ec2')
        else:
            # Fallback to default session with region
            self.ec2_client = boto3.client('ec2', region_name='us-east-1')
    
    def remediate(self, issue):
        try:
            if issue['type'] == 'ec2':
                self.ec2_client.modify_instance_attribute(
                    InstanceId=issue['resource_id'],
                    NoPublicIpAddress=True
                )
                return {'status': 'success', 'message': 'Public IP removed'}
            return {'status': 'skipped', 'message': f"Unsupported issue type: {issue['type']}"}
        except Exception as e:
            error_msg = f"Error remediating {issue['type']} {issue['resource_id']}: {str(e)}"
            logger.error(error_msg)
            return {'status': 'failed', 'message': error_msg}