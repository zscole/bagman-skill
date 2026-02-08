"""
Bagman Secret Manager

Retrieve secrets from 1Password at runtime.
NEVER cache, persist, or log secrets.

Requires: 1Password CLI (op) - brew install 1password-cli
"""

import subprocess
import json
import shutil
from datetime import datetime, timezone
from typing import Dict, Optional, List
from dataclasses import dataclass
from functools import lru_cache
import logging

# Configure logging to avoid accidental secret exposure
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ensure secrets are NEVER logged
class SecretFilter(logging.Filter):
    """Filter to prevent accidental secret logging."""
    PATTERNS = ['key', 'secret', 'password', 'token', 'credential', 'session-key']
    
    def filter(self, record):
        msg = str(record.msg).lower()
        for pattern in self.PATTERNS:
            if pattern in msg and ('=' in msg or ':' in msg):
                record.msg = "[REDACTED - potential secret in log]"
        return True

for handler in logging.root.handlers:
    handler.addFilter(SecretFilter())


@dataclass
class SessionKeyCredentials:
    """Validated session key credentials from 1Password."""
    session_key: str
    smart_account: str
    chain_id: int
    expires: Optional[datetime]
    spending_limit: Optional[str]
    allowed_contracts: List[str]
    allowed_methods: List[str]
    item_name: str
    
    def is_expired(self) -> bool:
        """Check if session key has expired."""
        if not self.expires:
            return False
        return datetime.now(timezone.utc) > self.expires
    
    def time_remaining(self) -> Optional[str]:
        """Human-readable time until expiry."""
        if not self.expires:
            return "No expiry"
        
        delta = self.expires - datetime.now(timezone.utc)
        if delta.total_seconds() <= 0:
            return "Expired"
        
        hours = int(delta.total_seconds() // 3600)
        minutes = int((delta.total_seconds() % 3600) // 60)
        
        if hours > 24:
            return f"{hours // 24}d {hours % 24}h"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"


class SecretManager:
    """
    1Password-backed secret manager for AI agents.
    
    Design principles:
    - Secrets retrieved on-demand, never cached
    - Automatic expiry validation
    - Structured error messages (no secret leakage)
    - Timeout protection
    """
    
    DEFAULT_VAULT = "Agent-Credentials"
    DEFAULT_TIMEOUT = 30
    
    def __init__(self, vault: str = None):
        """
        Initialize secret manager.
        
        Args:
            vault: 1Password vault name (default: Agent-Credentials)
        """
        self.vault = vault or self.DEFAULT_VAULT
        self._verify_cli()
    
    @staticmethod
    @lru_cache(maxsize=1)
    def _verify_cli() -> bool:
        """Verify 1Password CLI is installed and authenticated."""
        if not shutil.which("op"):
            raise RuntimeError(
                "1Password CLI (op) not found.\n"
                "Install: brew install 1password-cli\n"
                "Auth: eval $(op signin)"
            )
        
        # Check if signed in
        try:
            subprocess.run(
                ["op", "account", "list", "--format=json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            return True
        except subprocess.CalledProcessError:
            raise RuntimeError(
                "1Password CLI not authenticated.\n"
                "Run: eval $(op signin)"
            )
    
    def get_session_key(self, item_name: str) -> SessionKeyCredentials:
        """
        Retrieve and validate session key from 1Password.
        
        Args:
            item_name: Name of the item in 1Password
            
        Returns:
            SessionKeyCredentials with all fields validated
            
        Raises:
            RuntimeError: If retrieval fails
            ValueError: If session key is expired or invalid
        """
        try:
            result = subprocess.run(
                ["op", "item", "get", item_name,
                 "--vault", self.vault,
                 "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=self.DEFAULT_TIMEOUT
            )
        except subprocess.CalledProcessError as e:
            # Don't expose stderr (might contain sensitive info)
            raise RuntimeError(
                f"Failed to retrieve '{item_name}' from vault '{self.vault}'. "
                "Verify item exists and you have access."
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Timeout retrieving '{item_name}'. "
                "Check network and 1Password status."
            )
        
        try:
            item = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise RuntimeError("Invalid response from 1Password CLI")
        
        # Parse fields
        fields = {f["label"]: f.get("value") for f in item.get("fields", [])}
        
        # Parse and validate expiry
        expires = None
        expires_str = fields.get("expires") or fields.get("valid-until")
        if expires_str:
            try:
                # Handle various ISO formats
                expires_str = expires_str.replace("Z", "+00:00")
                expires = datetime.fromisoformat(expires_str)
                
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
            except ValueError:
                logger.warning(f"Could not parse expiry date: {expires_str}")
        
        # Build credentials
        creds = SessionKeyCredentials(
            session_key=fields.get("session-key") or fields.get("key") or "",
            smart_account=fields.get("smart-account") or fields.get("address") or "",
            chain_id=int(fields.get("chain-id", 1)),
            expires=expires,
            spending_limit=fields.get("spending-limit"),
            allowed_contracts=[
                c.strip()
                for c in (fields.get("allowed-contracts") or "").split(",")
                if c.strip()
            ],
            allowed_methods=[
                m.strip()
                for m in (fields.get("allowed-methods") or "").split(",")
                if m.strip()
            ],
            item_name=item_name,
        )
        
        # Validate
        if not creds.session_key:
            raise ValueError(f"Item '{item_name}' has no session-key field")
        
        if creds.is_expired():
            raise ValueError(
                f"Session key '{item_name}' has expired. "
                "Request renewal from operator."
            )
        
        return creds
    
    def read_secret(self, reference: str) -> str:
        """
        Read a single secret value using op:// reference.
        
        Args:
            reference: 1Password reference (e.g., op://Vault/Item/field)
            
        Returns:
            Secret value (string)
        """
        if not reference.startswith("op://"):
            raise ValueError("Reference must start with op://")
        
        try:
            result = subprocess.run(
                ["op", "read", reference],
                capture_output=True,
                text=True,
                check=True,
                timeout=self.DEFAULT_TIMEOUT
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            raise RuntimeError(
                f"Failed to read secret reference. "
                "Verify path and permissions."
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Timeout reading secret")
    
    def list_items(self, tags: List[str] = None) -> List[Dict]:
        """
        List items in the vault (metadata only, no secrets).
        
        Args:
            tags: Optional list of tags to filter by
            
        Returns:
            List of item metadata (id, title, tags, created, updated)
        """
        cmd = ["op", "item", "list", "--vault", self.vault, "--format=json"]
        
        if tags:
            cmd.extend(["--tags", ",".join(tags)])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=self.DEFAULT_TIMEOUT
            )
            items = json.loads(result.stdout)
            
            # Return only safe metadata
            return [
                {
                    "id": item.get("id"),
                    "title": item.get("title"),
                    "tags": item.get("tags", []),
                    "created_at": item.get("created_at"),
                    "updated_at": item.get("updated_at"),
                }
                for item in items
            ]
        except subprocess.CalledProcessError:
            raise RuntimeError(f"Failed to list items in vault '{self.vault}'")
    
    def inject_to_env(self, mappings: Dict[str, str]) -> Dict[str, str]:
        """
        Retrieve multiple secrets and return as environment dict.
        DO NOT persist to actual environment.
        
        Args:
            mappings: Dict of ENV_VAR_NAME -> op://reference
            
        Returns:
            Dict suitable for subprocess.run(env=...)
        """
        env = {}
        for env_var, reference in mappings.items():
            env[env_var] = self.read_secret(reference)
        return env


# Convenience function
def get_session_key(item_name: str, vault: str = None) -> SessionKeyCredentials:
    """
    Quick retrieval of session key.
    
    Example:
        creds = get_session_key("trading-bot-session")
        client.set_signer(creds.session_key)
    """
    manager = SecretManager(vault=vault)
    return manager.get_session_key(item_name)


# CLI usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Bagman Secret Manager")
        print("-" * 40)
        print("Usage:")
        print("  python secret_manager.py <item-name>     # Get session key")
        print("  python secret_manager.py --list          # List items")
        print("")
        print("Examples:")
        print("  python secret_manager.py trading-bot-session")
        print("  python secret_manager.py --list --vault=Production")
        sys.exit(0)
    
    # Parse args
    vault = None
    for arg in sys.argv[1:]:
        if arg.startswith("--vault="):
            vault = arg.split("=")[1]
    
    manager = SecretManager(vault=vault)
    
    if sys.argv[1] == "--list":
        print(f"Items in vault '{manager.vault}':")
        print("-" * 40)
        try:
            items = manager.list_items()
            for item in items:
                tags = ", ".join(item.get("tags", [])) or "no tags"
                print(f"  📄 {item['title']} ({tags})")
            print(f"\nTotal: {len(items)} items")
        except Exception as e:
            print(f"❌ Error: {e}")
            sys.exit(1)
    else:
        item_name = sys.argv[1]
        try:
            creds = manager.get_session_key(item_name)
            print(f"✅ Retrieved: {item_name}")
            print(f"   Smart Account: {creds.smart_account}")
            print(f"   Chain ID: {creds.chain_id}")
            print(f"   Time Remaining: {creds.time_remaining()}")
            print(f"   Spending Limit: {creds.spending_limit or 'unlimited'}")
            print(f"   Allowed Contracts: {len(creds.allowed_contracts)}")
            print(f"   Allowed Methods: {len(creds.allowed_methods)}")
            print(f"   Session Key: {creds.session_key[:8]}...{creds.session_key[-4:]}")
        except Exception as e:
            print(f"❌ Error: {e}")
            sys.exit(1)
