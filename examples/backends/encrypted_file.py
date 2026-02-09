"""
Local encrypted file backend using age encryption.

Requires: brew install age

Secrets are stored in ~/.bagman/secrets.age
Encrypted with a passphrase or age identity.
"""

import subprocess
import shutil
import json
import os
from pathlib import Path
from typing import Optional, List
from getpass import getpass

from .base import SecretBackend, SecretNotFoundError


class EncryptedFileBackend(SecretBackend):
    """
    Local encrypted file backend using age.
    
    Stores all secrets in a single encrypted JSON file.
    Decrypted in memory, never written to disk unencrypted.
    """
    
    name = "encrypted_file"
    
    def __init__(self, path: Optional[str] = None, identity_file: Optional[str] = None):
        self.path = Path(path or os.path.expanduser("~/.bagman/secrets.age"))
        self.identity_file = identity_file  # Optional age identity file
        self._cache: Optional[dict] = None
        self._passphrase: Optional[str] = None
    
    @classmethod
    def is_available(cls) -> bool:
        """Check if age is installed."""
        return shutil.which("age") is not None
    
    def _ensure_dir(self):
        """Create secrets directory if needed."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
    
    def _get_passphrase(self) -> str:
        """Get passphrase from cache or prompt."""
        if self._passphrase:
            return self._passphrase
        
        # Try environment variable first
        env_pass = os.environ.get("BAGMAN_PASSPHRASE")
        if env_pass:
            self._passphrase = env_pass
            return env_pass
        
        # Prompt user
        self._passphrase = getpass("Bagman passphrase: ")
        return self._passphrase
    
    def _load(self) -> dict:
        """Load and decrypt secrets file."""
        if self._cache is not None:
            return self._cache
        
        if not self.path.exists():
            self._cache = {}
            return self._cache
        
        try:
            if self.identity_file:
                # Decrypt with identity file
                result = subprocess.run(
                    ["age", "-d", "-i", self.identity_file, str(self.path)],
                    capture_output=True,
                    text=True,
                    check=True
                )
            else:
                # Decrypt with passphrase
                passphrase = self._get_passphrase()
                result = subprocess.run(
                    ["age", "-d"],
                    input=passphrase + "\n",
                    capture_output=True,
                    text=True,
                    check=True,
                    stdin=subprocess.PIPE,
                    env={**os.environ, "AGE_PASSPHRASE": passphrase}
                )
                # age -d reads from file, we need different approach
                proc = subprocess.Popen(
                    ["age", "-d", str(self.path)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = proc.communicate(input=passphrase)
                if proc.returncode != 0:
                    raise subprocess.CalledProcessError(proc.returncode, "age", stderr)
                result_text = stdout
            
            self._cache = json.loads(result.stdout if hasattr(result, 'stdout') else result_text)
            return self._cache
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to decrypt secrets: {e}")
    
    def _save(self):
        """Encrypt and save secrets file."""
        self._ensure_dir()
        data = json.dumps(self._cache or {}, indent=2)
        
        try:
            if self.identity_file:
                # Get public key from identity
                result = subprocess.run(
                    ["age-keygen", "-y", self.identity_file],
                    capture_output=True,
                    text=True,
                    check=True
                )
                recipient = result.stdout.strip()
                
                proc = subprocess.Popen(
                    ["age", "-r", recipient, "-o", str(self.path)],
                    stdin=subprocess.PIPE,
                    text=True
                )
                proc.communicate(input=data)
            else:
                # Encrypt with passphrase
                passphrase = self._get_passphrase()
                proc = subprocess.Popen(
                    ["age", "-p", "-o", str(self.path)],
                    stdin=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env={**os.environ, "AGE_PASSPHRASE": passphrase}
                )
                proc.communicate(input=data)
                
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to encrypt secrets: {e}")
    
    def get(self, key: str) -> str:
        """Retrieve secret from encrypted file."""
        secrets = self._load()
        if key not in secrets:
            raise SecretNotFoundError(f"Secret '{key}' not found")
        
        entry = secrets[key]
        if isinstance(entry, dict):
            return entry.get("value", entry.get("password", ""))
        return entry
    
    def set(self, key: str, value: str, metadata: Optional[dict] = None) -> None:
        """Store secret in encrypted file."""
        self._load()
        
        entry = {"value": value}
        if metadata:
            entry.update(metadata)
        
        self._cache[key] = entry
        self._save()
    
    def delete(self, key: str) -> None:
        """Delete secret from encrypted file."""
        secrets = self._load()
        if key not in secrets:
            raise SecretNotFoundError(f"Secret '{key}' not found")
        
        del self._cache[key]
        self._save()
    
    def list(self) -> List[str]:
        """List all secret keys."""
        return list(self._load().keys())
