"""
Environment variable backend.

Fallback backend that reads from environment variables.
Useful for CI/CD and containerized environments.

Secrets should be prefixed with BAGMAN_ (e.g., BAGMAN_MY_SECRET).
"""

import os
from typing import Optional, List

from .base import SecretBackend, SecretNotFoundError


class EnvBackend(SecretBackend):
    """
    Environment variable backend.
    
    Reads secrets from environment variables with BAGMAN_ prefix.
    Example: BAGMAN_TRADING_BOT_KEY -> get("trading-bot-key")
    """
    
    name = "env"
    prefix = "BAGMAN_"
    
    @classmethod
    def is_available(cls) -> bool:
        """Always available."""
        return True
    
    def _env_key(self, key: str) -> str:
        """Convert key to environment variable name."""
        # trading-bot-key -> BAGMAN_TRADING_BOT_KEY
        env_name = key.upper().replace("-", "_").replace(" ", "_")
        return f"{self.prefix}{env_name}"
    
    def get(self, key: str) -> str:
        """Retrieve secret from environment."""
        env_key = self._env_key(key)
        value = os.environ.get(env_key)
        if value is None:
            raise SecretNotFoundError(
                f"Secret '{key}' not found in environment. "
                f"Set {env_key} to use this secret."
            )
        return value
    
    def set(self, key: str, value: str, metadata: Optional[dict] = None) -> None:
        """
        'Store' secret in environment.
        
        Note: This only sets it for the current process.
        For persistence, export in shell or use another backend.
        """
        env_key = self._env_key(key)
        os.environ[env_key] = value
    
    def delete(self, key: str) -> None:
        """Remove secret from environment."""
        env_key = self._env_key(key)
        if env_key in os.environ:
            del os.environ[env_key]
        else:
            raise SecretNotFoundError(f"Secret '{key}' not found in environment")
    
    def list(self) -> List[str]:
        """List all BAGMAN_ prefixed environment variables."""
        keys = []
        for env_key in os.environ:
            if env_key.startswith(self.prefix):
                # BAGMAN_TRADING_BOT_KEY -> trading-bot-key
                key = env_key[len(self.prefix):].lower().replace("_", "-")
                keys.append(key)
        return keys
