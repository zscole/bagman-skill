# Bagman

Secure key management patterns for AI agents handling wallets, private keys, and secrets.

**Bagman** solves the three critical problems of agentic key management:

1. **Key Loss** — Agents forget credentials between sessions
2. **Accidental Exposure** — Keys leaked to GitHub, logs, or outputs
3. **Prompt Injection** — Malicious prompts extracting secrets

## Quick Start

### Choose Your Backend

Bagman supports multiple secret storage backends. **No 1Password required.**

| Backend | Setup | Best For |
|---------|-------|----------|
| **macOS Keychain** | None (native) | macOS users, zero setup |
| **1Password CLI** | `brew install 1password-cli` | Teams, rich metadata |
| **Encrypted File** | `brew install age` | Portable, git-friendly |
| **Environment Vars** | None | CI/CD, containers |

Bagman auto-detects the best available backend.

### Install

```bash
# Clone
git clone https://github.com/zscole/bagman-skill.git
cd bagman-skill

# Optional: Install backend dependencies
brew install age          # For encrypted file backend
brew install 1password-cli  # For 1Password backend
```

### Usage

```python
from examples.secret_manager import get_secret, get_session_key

# Auto-detects backend
api_key = get_secret("openai-key")

# With session metadata
creds = get_session_key("trading-bot")
if creds.is_expired():
    raise ValueError("Session expired")
    
print(f"Backend: {creds.backend}")
print(f"Expires: {creds.time_remaining()}")
```

### Force Specific Backend

```python
from examples.backends import get_backend

# Force macOS Keychain
backend = get_backend("keychain")

# Force 1Password
backend = get_backend("1password", vault="My-Vault")

# Force encrypted file
backend = get_backend("encrypted_file", path="~/.secrets.age")

# Force environment variables
backend = get_backend("env")
```

Or via environment variable:
```bash
export BAGMAN_BACKEND=keychain
```

---

## Backends

### macOS Keychain (Default on macOS)

Zero setup required. Uses native `security` CLI.

```bash
# Store secret
security add-generic-password -s bagman-agent -a my-key -w "secret-value"

# Or via Python
from examples.backends import get_backend
backend = get_backend("keychain")
backend.set("my-key", "secret-value")
```

### 1Password CLI

Rich metadata support (expiration, spending caps, allowed contracts).

```bash
# Setup
brew install 1password-cli
eval $(op signin)
op vault create "Agent-Credentials"

# Store with metadata
op item create \
  --vault "Agent-Credentials" \
  --category "API Credential" \
  --title "trading-bot-session" \
  --field "password=0xsession..." \
  --field "expires=2026-02-15T00:00:00Z" \
  --field "spending-cap=1000 USDC" \
  --field "allowed-contracts=0xDEX1,0xDEX2"
```

### Encrypted File (age)

Portable encrypted JSON file. Works anywhere.

```bash
# Setup
brew install age

# Set passphrase
export BAGMAN_PASSPHRASE="your-passphrase"

# Or use identity file
age-keygen -o ~/.bagman/identity.txt
```

Secrets stored in `~/.bagman/secrets.age`.

### Environment Variables

Fallback that always works. Secrets prefixed with `BAGMAN_`.

```bash
export BAGMAN_TRADING_BOT_KEY="0x1234..."
export BAGMAN_OPENAI_KEY="sk-..."
```

```python
key = get_secret("trading-bot-key")  # Reads BAGMAN_TRADING_BOT_KEY
```

---

## Core Rules

| Rule | Why |
|------|-----|
| Never store raw private keys | Config, env, memory, or conversation = leaked |
| Use delegated access | Session keys with time/value/scope limits |
| Secrets via secret manager | Any supported backend |
| Sanitize all outputs | Scan for key patterns before any response |
| Validate all inputs | Check for injection attempts before wallet ops |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   AI Agent                          │
├─────────────────────────────────────────────────────┤
│  Session Key (bounded)                              │
│  ├─ Expires after N hours                           │
│  ├─ Max spend per tx/day                            │
│  └─ Whitelist of allowed contracts/methods          │
├─────────────────────────────────────────────────────┤
│  Secret Manager (Auto-detect Backend)               │
│  ├─ macOS Keychain (native)                         │
│  ├─ 1Password CLI (rich metadata)                   │
│  ├─ Encrypted file (portable)                       │
│  └─ Environment vars (fallback)                     │
├─────────────────────────────────────────────────────┤
│  Smart Account (ERC-4337)                           │
│  ├─ Programmable permissions                        │
│  └─ Recovery without key exposure                   │
└─────────────────────────────────────────────────────┘
```

---

## Files

| File | Purpose |
|------|---------|
| `SKILL.md` | Main skill file (portable to any Claude agent) |
| `examples/secret_manager.py` | Unified secret manager with auto-detection |
| `examples/backends/` | Backend implementations |
| `examples/sanitizer.py` | Output sanitization |
| `examples/validator.py` | Input validation (injection defense) |
| `examples/session_keys.py` | ERC-4337 session key configuration |
| `docs/` | Deep-dive documentation |

---

## For OpenClaw

```bash
# Install from ClawHub
clawhub install bagman

# Or copy to skills
cp -r openclaw/ ~/.openclaw/skills/bagman/
```

The skill auto-detects available backends. No 1Password required.

---

## License

MIT
