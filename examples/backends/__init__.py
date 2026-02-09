"""
Multi-backend secret manager for AI agents.

Supports:
- macOS Keychain (default on macOS, no setup required)
- 1Password CLI (op)
- Local encrypted file (age encryption)
- Environment variables (fallback)
- AWS Secrets Manager
- HashiCorp Vault
"""

from .base import SecretBackend, SecretNotFoundError
from .auto import get_backend, list_available_backends

__all__ = [
    'SecretBackend',
    'SecretNotFoundError', 
    'get_backend',
    'list_available_backends',
]
