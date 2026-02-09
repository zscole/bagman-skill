#!/usr/bin/env python3
"""
Unified Secret Manager for AI Agents

Auto-detects and uses the best available backend:
1. macOS Keychain (native, no setup on macOS)
2. 1Password CLI (rich metadata, best UX)
3. Local encrypted file (age encryption)
4. Environment variables (fallback)

Usage:
    from secret_manager import get_secret, get_session_key
    
    # Simple secret retrieval
    api_key = get_secret("openai-key")
    
    # Session credential with metadata
    creds = get_session_key("trading-bot")
    if creds.is_expired():
        raise ValueError("Session expired")
    print(f"Using key from {creds.backend}, expires in {creds.time_remaining()}")
"""

from typing import Optional
from backends import get_backend, list_available_backends, SecretNotFoundError
from backends.base import SessionCredential


# Global backend instance (lazy init)
_backend = None


def _get_backend():
    global _backend
    if _backend is None:
        _backend = get_backend()
        print(f"[bagman] Using secret backend: {_backend.name}")
    return _backend


def get_secret(key: str, backend: Optional[str] = None) -> str:
    """
    Retrieve a secret by key.
    
    Args:
        key: Secret name (e.g., "trading-bot-key", "openai-api")
        backend: Force specific backend, or None for auto-detect
    
    Returns:
        Secret value
    
    Raises:
        SecretNotFoundError if not found
    
    Example:
        api_key = get_secret("openai-key")
    """
    if backend:
        return get_backend(backend).get(key)
    return _get_backend().get(key)


def get_session_key(key: str, backend: Optional[str] = None) -> SessionCredential:
    """
    Retrieve a session credential with metadata.
    
    Returns a SessionCredential object with:
    - key: The actual secret value
    - expires: Optional expiration datetime
    - spending_cap: Optional spending limit string
    - allowed_contracts: Optional list of allowed contract addresses
    - backend: Which backend provided this credential
    
    Example:
        creds = get_session_key("trading-bot-session")
        
        if creds.is_expired():
            raise ValueError("Session expired - request new key from operator")
        
        print(f"Time remaining: {creds.time_remaining()}")
        print(f"Spending cap: {creds.spending_cap}")
        print(f"Allowed contracts: {creds.allowed_contracts}")
        
        # Use the key (never log it!)
        client.set_signer(creds.key)
    """
    if backend:
        return get_backend(backend).get_session_credential(key)
    return _get_backend().get_session_credential(key)


def set_secret(key: str, value: str, backend: Optional[str] = None, **metadata) -> None:
    """
    Store a secret.
    
    Args:
        key: Secret name
        value: Secret value
        backend: Force specific backend, or None for auto-detect
        **metadata: Additional metadata (expires, spending_cap, allowed_contracts)
    
    Example:
        set_secret(
            "trading-bot-session",
            "0x1234...",
            expires="2026-02-15T00:00:00Z",
            spending_cap="1000 USDC",
            allowed_contracts=["0xDEX1", "0xDEX2"]
        )
    """
    if backend:
        get_backend(backend).set(key, value, metadata if metadata else None)
    else:
        _get_backend().set(key, value, metadata if metadata else None)


def delete_secret(key: str, backend: Optional[str] = None) -> None:
    """Delete a secret."""
    if backend:
        get_backend(backend).delete(key)
    else:
        _get_backend().delete(key)


def list_secrets(backend: Optional[str] = None) -> list:
    """List all secret keys (not values)."""
    if backend:
        return get_backend(backend).list()
    return _get_backend().list()


# CLI for testing
if __name__ == "__main__":
    import sys
    
    print("Bagman Secret Manager")
    print("=" * 40)
    print(f"Available backends: {list_available_backends()}")
    
    backend = _get_backend()
    print(f"Selected backend: {backend.name}")
    print()
    
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        
        if cmd == "get" and len(sys.argv) > 2:
            key = sys.argv[2]
            try:
                value = get_secret(key)
                print(f"{key}: {value[:8]}...{value[-4:]}" if len(value) > 12 else f"{key}: ***")
            except SecretNotFoundError as e:
                print(f"Error: {e}")
        
        elif cmd == "set" and len(sys.argv) > 3:
            key, value = sys.argv[2], sys.argv[3]
            set_secret(key, value)
            print(f"Stored: {key}")
        
        elif cmd == "list":
            secrets = list_secrets()
            print(f"Secrets ({len(secrets)}):")
            for s in secrets:
                print(f"  - {s}")
        
        elif cmd == "delete" and len(sys.argv) > 2:
            key = sys.argv[2]
            delete_secret(key)
            print(f"Deleted: {key}")
        
        else:
            print("Usage: secret_manager.py [get|set|list|delete] [key] [value]")
    else:
        print("Usage: secret_manager.py [get|set|list|delete] [key] [value]")
        print()
        print("Run with no args to see available backends.")
