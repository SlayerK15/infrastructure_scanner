# src/utils/config.py
import yaml
import os
from dotenv import load_dotenv


def load_config(config_path: str) -> Dict:
    """Load configuration from YAML file and environment variables."""
    # Load .env file
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Update config with environment variables
    if config['aws'].get('use_env_file'):
        config['aws']['access_key_id'] = os.getenv('AWS_ACCESS_KEY_ID')
        config['aws']['secret_access_key'] = os.getenv('AWS_SECRET_ACCESS_KEY')
    
    if 'EMAIL_APP_PASSWORD' in os.environ:
        config['notifications']['email']['password'] = os.getenv('EMAIL_APP_PASSWORD')
    
    return config