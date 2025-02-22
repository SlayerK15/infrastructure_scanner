# src/providers/ec2.py
import boto3
import logging

logger = logging.getLogger(__name__)

class EC2Scanner:
    def __init__(self, config):
        self.config = config
        self.ec2_client = boto3.client('ec2', region_name=config['aws']['region'])
    
    def scan(self):
        issues = []
        try:
            instances = self.ec2_client.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    if 'PublicIpAddress' in instance:
                        issues.append({
                            'type': 'ec2',
                            'resource_id': instance_id,
                            'severity': 'high',
                            'description': f'Instance {instance_id} has a public IP.',
                            'remediation': 'Remove the public IP.'
                        })
            logger.info(f"EC2 Scan completed with {len(issues)} issues.")
        except Exception as e:
            logger.error(f"Error scanning EC2: {str(e)}")
        return issues