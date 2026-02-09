"""
macOS Keychain backend.

Uses the `security` CLI tool to interact with Keychain.
No additional setup required on macOS.
"""

import subprocess
import shutil
from typing import Optional, List

from .base import SecretBackend, SecretNotFoundError, BackendNotAvailableError


class KeychainBackend(SecretBackend):
    """
    macOS Keychain backend using the `security` CLI.
    
    Secrets are stored as generic passwords in the login keychain
    with service name "bagman-agent".
    """
    
    name = "keychain"
    service = "bagman-agent"
    
    @classmethod
    def is_available(cls) -> bool:
        """Available on macOS with security CLI."""
        return shutil.which("security") is not None
    
    def get(self, key: str) -> str:
        """Retrieve secret from Keychain."""
        try:
            result = subprocess.run(
                [
                    "security", "find-generic-password",
                    "-s", self.service,
                    "-a", key,
                    "-w"  # Output password only
                ],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            raise SecretNotFoundError(f"Secret '{key}' not found in Keychain")
    
    def set(self, key: str, value: str, metadata: Optional[dict] = None) -> None:
        """Store secret in Keychain."""
        # Delete existing if present (update isn't atomic)
        try:
            self.delete(key)
        except SecretNotFoundError:
            pass
        
        # Add new secret
        subprocess.run(
            [
                "security", "add-generic-password",
                "-s", self.service,
                "-a", key,
                "-w", value,
                "-U"  # Update if exists
            ],
            check=True,
            capture_output=True
        )
    
    def delete(self, key: str) -> None:
        """Delete secret from Keychain."""
        try:
            subprocess.run(
                [
                    "security", "delete-generic-password",
                    "-s", self.service,
                    "-a", key
                ],
                check=True,
                capture_output=True
            )
        except subprocess.CalledProcessError:
            raise SecretNotFoundError(f"Secret '{key}' not found in Keychain")
    
    def list(self) -> List[str]:
        """List all bagman secrets in Keychain."""
        # security doesn't have a great way to list by service
        # We use dump-keychain and parse, or just return empty
        # For now, return empty - full impl would parse keychain dump
        return []
