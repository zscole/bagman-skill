"""
Auto-detection and selection of secret backends.
"""

from typing import List, Optional, Type
import os

from .base import SecretBackend, BackendNotAvailableError


# Import backends (order matters for auto-selection)
def _get_backend_classes() -> List[Type[SecretBackend]]:
    """Get all backend classes in priority order."""
    backends = []
    
    # Try importing each backend
    try:
        from .keychain import KeychainBackend
        backends.append(KeychainBackend)
    except ImportError:
        pass
    
    try:
        from .onepassword import OnePasswordBackend
        backends.append(OnePasswordBackend)
    except ImportError:
        pass
    
    try:
        from .encrypted_file import EncryptedFileBackend
        backends.append(EncryptedFileBackend)
    except ImportError:
        pass
    
    try:
        from .env import EnvBackend
        backends.append(EnvBackend)
    except ImportError:
        pass
    
    return backends


# Priority order for auto-selection
# Higher priority = preferred when available
BACKEND_PRIORITY = [
    "1password",      # Rich metadata, best UX
    "keychain",       # Native macOS, no setup
    "encrypted_file", # Works anywhere with age
    "env",            # Always available fallback
]


def list_available_backends() -> List[str]:
    """List all backends that are available on this system."""
    available = []
    for cls in _get_backend_classes():
        if cls.is_available():
            available.append(cls.name)
    return available


def get_backend(name: Optional[str] = None, **kwargs) -> SecretBackend:
    """
    Get a secret backend instance.
    
    Args:
        name: Specific backend name, or None for auto-detection
        **kwargs: Backend-specific configuration
    
    Returns:
        SecretBackend instance
    
    Raises:
        BackendNotAvailableError if requested backend isn't available
    
    Examples:
        # Auto-detect best available
        backend = get_backend()
        
        # Specific backend
        backend = get_backend("1password", vault="My-Vault")
        backend = get_backend("keychain")
        backend = get_backend("encrypted_file", path="~/.secrets.age")
    """
    backend_classes = {cls.name: cls for cls in _get_backend_classes()}
    
    if name:
        # Specific backend requested
        if name not in backend_classes:
            raise BackendNotAvailableError(
                f"Unknown backend '{name}'. Available: {list(backend_classes.keys())}"
            )
        
        cls = backend_classes[name]
        if not cls.is_available():
            raise BackendNotAvailableError(
                f"Backend '{name}' is not available on this system. "
                f"Available backends: {list_available_backends()}"
            )
        
        return cls(**kwargs)
    
    # Auto-detect: try in priority order
    # Check for explicit preference via env var
    preferred = os.environ.get("BAGMAN_BACKEND")
    if preferred and preferred in backend_classes:
        cls = backend_classes[preferred]
        if cls.is_available():
            return cls(**kwargs)
    
    # Fall through priority list
    for backend_name in BACKEND_PRIORITY:
        if backend_name in backend_classes:
            cls = backend_classes[backend_name]
            if cls.is_available():
                return cls(**kwargs)
    
    raise BackendNotAvailableError(
        "No secret backend available. Install one of:\n"
        "  - 1Password CLI: brew install 1password-cli\n"
        "  - age (for encrypted file): brew install age\n"
        "  - Or set BAGMAN_* environment variables"
    )


def get_secret(key: str, backend: Optional[str] = None, **kwargs) -> str:
    """
    Convenience function to get a secret.
    
    Args:
        key: Secret name
        backend: Specific backend, or None for auto
        **kwargs: Backend config
    
    Returns:
        Secret value
    """
    return get_backend(backend, **kwargs).get(key)
