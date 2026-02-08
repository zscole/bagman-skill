"""
Bagman Secret Manager

Retrieve secrets from 1Password at runtime. Never cache or persist.
"""

import subprocess
import json
from datetime import datetime
from typing import Dict, Optional

class SecretManager:
    """1Password-backed secret manager for AI agents."""
    
    def __init__(self, vault: str = "Agent-Credentials"):
        self.vault = vault
    
    def get_session_key(self, item_name: str) -> Dict:
        """
        Retrieve and validate session key from 1Password.
        
        Returns dict with:
        - session_key: The actual key
        - smart_account: Associated smart account address
        - chain_id: Target chain
        - expires: Expiry timestamp
        - spending_limit: Max spend
        - allowed_contracts: List of permitted contracts
        - allowed_methods: List of permitted methods
        """
        try:
            result = subprocess.run(
                ["op", "item", "get", item_name, 
                 "--vault", self.vault, 
                 "--format", "json"],
                capture_output=True, 
                text=True, 
                check=True,
                timeout=30
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to retrieve secret: {e.stderr}")
        except FileNotFoundError:
            raise RuntimeError("1Password CLI (op) not found. Install: brew install 1password-cli")
        
        item = json.loads(result.stdout)
        fields = {f["label"]: f.get("value") for f in item.get("fields", [])}
        
        # Validate expiry
        expires_str = fields.get("expires")
        if expires_str:
            expires = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
            if datetime.now(expires.tzinfo) > expires:
                raise ValueError(f"Session key '{item_name}' has expired. Request renewal from operator.")
        
        return {
            "session_key": fields.get("session-key"),
            "smart_account": fields.get("smart-account"),
            "chain_id": int(fields.get("chain-id", 1)),
            "expires": expires_str,
            "spending_limit": fields.get("spending-limit"),
            "allowed_contracts": [c.strip() for c in fields.get("allowed-contracts", "").split(",") if c.strip()],
            "allowed_methods": [m.strip() for m in fields.get("allowed-methods", "").split(",") if m.strip()],
        }
    
    def read_secret(self, reference: str) -> str:
        """
        Read a single secret value using op:// reference.
        
        Example: op://Agents/my-agent/session-key
        """
        try:
            result = subprocess.run(
                ["op", "read", reference],
                capture_output=True,
                text=True,
                check=True,
                timeout=30
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to read secret: {e.stderr}")


# Usage example
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python secret_manager.py <item-name>")
        print("Example: python secret_manager.py trading-bot-session")
        sys.exit(1)
    
    item_name = sys.argv[1]
    manager = SecretManager()
    
    try:
        creds = manager.get_session_key(item_name)
        print(f"✅ Retrieved session key for: {item_name}")
        print(f"   Smart Account: {creds['smart_account']}")
        print(f"   Chain ID: {creds['chain_id']}")
        print(f"   Expires: {creds['expires']}")
        print(f"   Spending Limit: {creds['spending_limit']}")
        print(f"   Allowed Contracts: {len(creds['allowed_contracts'])}")
        print(f"   Session Key: {creds['session_key'][:8]}...{creds['session_key'][-4:] if creds['session_key'] else 'N/A'}")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
