"""
1Password CLI backend.

Requires: brew install 1password-cli && eval $(op signin)
"""

import subprocess
import shutil
import json
from typing import Optional, List
from datetime import datetime

from .base import SecretBackend, SecretNotFoundError, SessionCredential


class OnePasswordBackend(SecretBackend):
    """
    1Password backend using the `op` CLI.
    
    Secrets are stored in a vault (default: "Agent-Credentials").
    Supports rich metadata like expiration, spending caps, etc.
    """
    
    name = "1password"
    
    def __init__(self, vault: str = "Agent-Credentials"):
        self.vault = vault
    
    @classmethod
    def is_available(cls) -> bool:
        """Check if op CLI is installed and authenticated."""
        if not shutil.which("op"):
            return False
        # Check if signed in
        try:
            subprocess.run(
                ["op", "account", "get"],
                capture_output=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError:
            return False
    
    def get(self, key: str) -> str:
        """Retrieve secret from 1Password."""
        try:
            result = subprocess.run(
                ["op", "read", f"op://{self.vault}/{key}/password"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            raise SecretNotFoundError(f"Secret '{key}' not found in 1Password vault '{self.vault}'")
    
    def get_session_credential(self, key: str) -> SessionCredential:
        """Retrieve credential with full 1Password metadata."""
        try:
            result = subprocess.run(
                ["op", "item", "get", key, "--vault", self.vault, "--format", "json"],
                capture_output=True,
                text=True,
                check=True
            )
            item = json.loads(result.stdout)
            
            # Parse fields
            fields = {}
            for field in item.get("fields", []):
                label = field.get("label", "").lower().replace("-", "_").replace(" ", "_")
                fields[label] = field.get("value")
            
            # Get the main secret (password field or session-key)
            secret = fields.get("password") or fields.get("session_key") or fields.get("credential")
            if not secret:
                raise SecretNotFoundError(f"No password/session-key field in item '{key}'")
            
            # Parse expiration
            expires = None
            if fields.get("expires"):
                try:
                    expires = datetime.fromisoformat(fields["expires"].replace("Z", "+00:00"))
                except ValueError:
                    pass
            
            # Parse allowed contracts
            allowed_contracts = None
            if fields.get("allowed_contracts"):
                allowed_contracts = [c.strip() for c in fields["allowed_contracts"].split(",")]
            
            return SessionCredential(
                key=secret,
                expires=expires,
                spending_cap=fields.get("spending_cap"),
                allowed_contracts=allowed_contracts,
                backend=self.name
            )
            
        except subprocess.CalledProcessError:
            raise SecretNotFoundError(f"Secret '{key}' not found in 1Password")
    
    def set(self, key: str, value: str, metadata: Optional[dict] = None) -> None:
        """Store secret in 1Password."""
        metadata = metadata or {}
        
        # Build field arguments
        fields = [f"password={value}"]
        if metadata.get("expires"):
            fields.append(f"expires={metadata['expires']}")
        if metadata.get("spending_cap"):
            fields.append(f"spending-cap={metadata['spending_cap']}")
        if metadata.get("allowed_contracts"):
            contracts = ",".join(metadata["allowed_contracts"])
            fields.append(f"allowed-contracts={contracts}")
        
        cmd = [
            "op", "item", "create",
            "--vault", self.vault,
            "--category", "API Credential",
            "--title", key,
        ]
        for field in fields:
            cmd.extend(["--field", field])
        
        subprocess.run(cmd, check=True, capture_output=True)
    
    def delete(self, key: str) -> None:
        """Delete secret from 1Password."""
        try:
            subprocess.run(
                ["op", "item", "delete", key, "--vault", self.vault],
                check=True,
                capture_output=True
            )
        except subprocess.CalledProcessError:
            raise SecretNotFoundError(f"Secret '{key}' not found in 1Password")
    
    def list(self) -> List[str]:
        """List all items in vault."""
        try:
            result = subprocess.run(
                ["op", "item", "list", "--vault", self.vault, "--format", "json"],
                capture_output=True,
                text=True,
                check=True
            )
            items = json.loads(result.stdout)
            return [item["title"] for item in items]
        except subprocess.CalledProcessError:
            return []
