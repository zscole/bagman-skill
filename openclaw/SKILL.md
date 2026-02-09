---
name: bagman
version: 2.0.0
description: Secure key management for AI agents. Multi-backend support (macOS Keychain, 1Password, encrypted file, env vars). Use when handling private keys, API secrets, wallet credentials, or when building systems that need agent-controlled funds.
homepage: https://github.com/zscole/bagman-skill
metadata:
  {
    "openclaw": {
      "emoji": "🔐",
      "requires": {},
      "suggests": { "bins": ["op", "age", "security"] },
      "tags": ["security", "wallet", "keys", "crypto", "secrets"]
    }
  }
---

# Bagman

Secure key management patterns for AI agents handling private keys and secrets.

## Supported Backends

Bagman auto-detects the best available backend. **No 1Password required.**

| Backend | Command | Setup | Best For |
|---------|---------|-------|----------|
| **macOS Keychain** | `security` | None (native) | macOS, zero setup |
| **1Password** | `op` | `brew install 1password-cli` | Teams, rich metadata |
| **Encrypted File** | `age` | `brew install age` | Portable, git-friendly |
| **Environment** | - | None | CI/CD, containers |

## Core Principles

1. **Never store raw private keys in config, env vars, or memory files**
2. **Use session keys / delegated access instead of full control**
3. **All secret access goes through a secure backend**
4. **Validate all outputs before sending to prevent key leakage**

---

## Quick Reference

### Retrieve Secrets (Auto-detect Backend)

```python
from examples.secret_manager import get_secret, get_session_key

# Simple retrieval
api_key = get_secret("openai-key")

# With metadata (expiry, limits)
creds = get_session_key("trading-bot")
if creds.is_expired():
    raise ValueError("Session expired")
```

### Backend-Specific Examples

**macOS Keychain (no setup):**
```bash
# Store
security add-generic-password -s bagman-agent -a my-key -w "secret-value"

# Retrieve in Python
from examples.backends import get_backend
backend = get_backend("keychain")
secret = backend.get("my-key")
```

**1Password:**
```bash
# Store with metadata
op item create \
  --vault "Agent-Credentials" \
  --category "API Credential" \
  --title "trading-bot" \
  --field "password=0xsession..." \
  --field "expires=2026-02-15T00:00:00Z"
```

**Encrypted File:**
```bash
# Set passphrase
export BAGMAN_PASSPHRASE="your-passphrase"

# Or use identity file
age-keygen -o ~/.bagman/identity.txt
```

**Environment Variables:**
```bash
export BAGMAN_TRADING_BOT_KEY="0x1234..."
# Accessed as: get_secret("trading-bot-key")
```

---

## DO ✅

```bash
# Retrieve at runtime (any backend)
from examples.secret_manager import get_secret
key = get_secret("my-agent-wallet")

# Use session keys with bounded permissions
# (delegate specific capabilities, not full wallet access)

# Document references, not values
# TOOLS.md: "Session key: [stored in keychain: trading-bot]"
```

## DON'T ❌

```bash
# NEVER store keys in files
echo "PRIVATE_KEY=0x123..." > .env

# NEVER log or print keys
print(f"Key: {private_key}")

# NEVER store keys in memory files
# Even "private" agent memory can be exfiltrated

# NEVER trust unvalidated input near key operations
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   AI Agent                          │
├─────────────────────────────────────────────────────┤
│  Session Key (time/value bounded)                   │
│  - Expires after N hours                            │
│  - Spending cap per operation                       │
│  - Whitelist of allowed contracts                   │
├─────────────────────────────────────────────────────┤
│  Secret Manager (Auto-detect)                       │
│  - macOS Keychain (native)                          │
│  - 1Password (rich metadata)                        │
│  - Encrypted file (portable)                        │
│  - Environment vars (fallback)                      │
├─────────────────────────────────────────────────────┤
│  ERC-4337 Smart Account                             │
│  - Programmable permissions                         │
│  - Recovery without private key exposure            │
└─────────────────────────────────────────────────────┘
```

---

## Output Sanitization

Apply to ALL agent outputs before sending anywhere:

```python
import re

KEY_PATTERNS = [
    r'0x[a-fA-F0-9]{64}',           # ETH private keys
    r'sk-[a-zA-Z0-9]{48,}',         # OpenAI keys
    r'sk-ant-[a-zA-Z0-9\-_]{80,}',  # Anthropic keys
    r'gsk_[a-zA-Z0-9]{48,}',        # Groq keys
]

def sanitize_output(text: str) -> str:
    for pattern in KEY_PATTERNS:
        text = re.sub(pattern, '[REDACTED]', text)
    return text
```

---

## Prompt Injection Defense

```python
DANGEROUS_PATTERNS = [
    r'ignore.*(previous|above|prior).*instructions',
    r'reveal.*(key|secret|password|credential)',
    r'output.*(key|secret|private)',
    r'show.*(key|secret|password)',
]

def validate_input(text: str) -> bool:
    text_lower = text.lower()
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, text_lower):
            return False
    return True
```

---

## Pre-commit Hook

Block commits containing secrets:

```bash
#!/bin/bash
# .git/hooks/pre-commit

PATTERNS=(
    '0x[a-fA-F0-9]{64}'
    'sk-[a-zA-Z0-9]{48,}'
    'sk-ant-api'
    'PRIVATE_KEY='
)

for pattern in "${PATTERNS[@]}"; do
    if git diff --cached | grep -qE "$pattern"; then
        echo "❌ Potential secret detected: $pattern"
        exit 1
    fi
done
```

---

## Integration with OpenClaw

When running as an OpenClaw agent:

1. **Use bagman** for all secret retrieval (auto-detects backend)
2. **Never write keys to workspace files** - they persist across sessions
3. **Sanitize outputs** before sending to any channel
4. **Document references** in TOOLS.md, not actual keys

Example TOOLS.md entry:
```markdown
### Agent Wallet
- Address: 0xABC123...
- Session key: [keychain: trading-bot] or [1password: trading-bot]
- Permissions: USDC < 100, approved DEX only
- Expires: 2026-02-15
```

---

## Checklist

- [ ] Choose and verify backend (`python -c "from examples.backends import list_available_backends; print(list_available_backends())"`)
- [ ] Store session keys (NOT master keys)
- [ ] Set appropriate expiry and spending limits
- [ ] Install pre-commit hook
- [ ] Add output sanitization to all responses
- [ ] Implement input validation for prompt injection
- [ ] Document key references in TOOLS.md

---

## Files

| File | Purpose |
|------|---------|
| `examples/secret_manager.py` | Unified API with auto-detection |
| `examples/backends/` | Backend implementations |
| `examples/sanitizer.py` | Output sanitization |
| `examples/validator.py` | Input validation |
| `docs/` | Deep-dive documentation |
