"""
Base class for secret backends.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List


class SecretNotFoundError(Exception):
    """Secret not found in backend."""
    pass


class BackendNotAvailableError(Exception):
    """Backend is not available on this system."""
    pass


@dataclass
class SessionCredential:
    """A retrieved session credential with metadata."""
    key: str
    expires: Optional[datetime] = None
    spending_cap: Optional[str] = None
    allowed_contracts: Optional[List[str]] = None
    backend: str = "unknown"
    
    def is_expired(self) -> bool:
        if self.expires is None:
            return False
        return datetime.now() > self.expires
    
    def time_remaining(self) -> Optional[str]:
        if self.expires is None:
            return None
        delta = self.expires - datetime.now()
        if delta.total_seconds() < 0:
            return "EXPIRED"
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, _ = divmod(remainder, 60)
        return f"{hours}h {minutes}m"


class SecretBackend(ABC):
    """Abstract base class for secret storage backends."""
    
    name: str = "base"
    
    @classmethod
    @abstractmethod
    def is_available(cls) -> bool:
        """Check if this backend is available on the current system."""
        pass
    
    @abstractmethod
    def get(self, key: str) -> str:
        """Retrieve a secret by key. Raises SecretNotFoundError if not found."""
        pass
    
    @abstractmethod
    def set(self, key: str, value: str, metadata: Optional[dict] = None) -> None:
        """Store a secret. metadata can include expires, spending_cap, etc."""
        pass
    
    @abstractmethod
    def delete(self, key: str) -> None:
        """Delete a secret."""
        pass
    
    @abstractmethod
    def list(self) -> List[str]:
        """List all secret keys (not values)."""
        pass
    
    def get_session_credential(self, key: str) -> SessionCredential:
        """
        Retrieve a session credential with full metadata.
        Override in backends that support metadata.
        """
        value = self.get(key)
        return SessionCredential(key=value, backend=self.name)
