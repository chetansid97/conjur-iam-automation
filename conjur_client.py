#!/usr/bin/env python3
"""
Conjur IAM Automation Client
Authenticates to CyberArk Conjur using AWS IAM and retrieves secrets
"""

import json
import argparse
from datetime import datetime
import logging
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ConjurIAMClient:
    """Client for authenticating to Conjur using AWS IAM and retrieving secrets"""
    
    def __init__(self, appliance_url: str, account: str, authn_iam_service_id: str, username: str):
        self.appliance_url = appliance_url.rstrip('/')
        self.account = account
        self.authn_iam_service_id = authn_iam_service_id
        self.username = username
        self.api_key = None
        self.access_token = None
        
    def create_iam_api_key(self) -> str:
        """Generate IAM API key (simulated for demo)"""
        logger.info("Generating IAM API key...")
        simulated_api_key = "SimulatedAWSIAMSignature_v1_" + datetime.now().strftime("%Y%m%d%H%M%S")
        self.api_key = simulated_api_key
        return simulated_api_key
    
    def get_session_token(self) -> Dict[str, Any]:
        """Exchange IAM API key for Conjur access token (simulated)"""
        if not self.api_key:
            self.create_iam_api_key()
            
        logger.info("Requesting Conjur access token...")
        
        simulated_token = {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJob3N0L21pY3Jvc2VydmljZS9pYW0tcm9sZSIsImFjY291bnQiOiJkZXYiLCJleHAiOjE3MTAwMDAwMDB9.dummy_signature",
            "token_type": "Bearer",
            "expires_in": 480
        }
        
        self.access_token = simulated_token
        logger.info("Successfully authenticated to Conjur")
        return simulated_token
    
    def fetch_secret(self, variable_path: str) -> str:
        """Fetch secret from Conjur (simulated)"""
        if not self.access_token:
            self.get_session_token()
            
        logger.info(f"Fetching secret: {variable_path}")
        simulated_secret = f"secret_value_for_{variable_path.split('/')[-1]}"
        
        # Audit logging
        self._log_access(variable_path)
        
        return simulated_secret
    
    def _log_access(self, variable_path: str):
        """Audit logging for compliance"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "username": self.username,
            "variable_path": variable_path,
            "action": "fetch",
            "status": "success"
        }
        
        with open("conjur_audit.log", "a") as f:
            f.write(json.dumps(log_entry) + "\n")

def main():
    parser = argparse.ArgumentParser(description="Conjur IAM Automation Client")
    parser.add_argument("--variable", required=True, help="Variable path to fetch")
    parser.add_argument("--url", default="https://conjur.example.com", help="Conjur appliance URL")
    parser.add_argument("--account", default="dev", help="Conjur account")
    parser.add_argument("--service-id", default="prod", help="IAM authenticator service ID")
    parser.add_argument("--username", default="host/myspace/123456789012/IAMRole", help="Conjur username")
    
    args = parser.parse_args()
    
    client = ConjurIAMClient(
        appliance_url=args.url,
        account=args.account,
        authn_iam_service_id=args.service_id,
        username=args.username
    )
    
    try:
        client.create_iam_api_key()
        client.get_session_token()
        secret = client.fetch_secret(args.variable)
        
        print("\n=== SUCCESS ====")
        print(f"Variable: {args.variable}")
        print(f"Secret: {secret}")
        print("=" * 50)
        
    except Exception as e:
        logger.error(f"Failed to fetch secret: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())