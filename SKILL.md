# Bagman

Secure key management patterns for AI agents handling wallets, private keys, and secrets.

## When to Use This Skill

- Agent needs wallet/blockchain access
- Handling API keys, credentials, or secrets
- Building systems where AI controls funds
- Preventing secret leakage via prompts or outputs

## Core Rules

1. **Never store raw private keys** - Not in config, env files, memory, or conversation
2. **Use delegated access** - Session keys with time/value/scope limits, not master keys
3. **Secrets via secret manager** - 1Password CLI, Vault, AWS Secrets Manager
4. **Sanitize all outputs** - Scan for key patterns before any response
5. **Validate all inputs** - Check for injection attempts before wallet operations

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   AI Agent                          │
├─────────────────────────────────────────────────────┤
│  Session Key (bounded)                              │
│  - Expires after N hours                            │
│  - Max spend per tx/day                             │
│  - Whitelist of allowed contracts                   │
├─────────────────────────────────────────────────────┤
│  Secret Manager (1Password/Vault)                   │
│  - Retrieve at runtime only                         │
│  - Never persist to disk                            │
│  - Audit trail of accesses                          │
├─────────────────────────────────────────────────────┤
│  Smart Account (ERC-4337)                           │
│  - Programmable permissions                         │
│  - Recovery without key exposure                    │
└─────────────────────────────────────────────────────┘
```

---

## Secret Retrieval

### 1Password CLI Pattern

```bash
# Retrieve at runtime (never store result)
SESSION_KEY=$(op read "op://Agents/my-agent/session-key")

# Run with injected secrets (never touch disk)
op run --env-file=.env.tpl -- python agent.py
```

### .env.tpl (committed to git - no secrets)

```
PRIVATE_KEY=op://Agents/trading-bot/session-key
RPC_URL=op://Infra/alchemy/sepolia-url
```

### Python

```python
import subprocess
import json

def get_secret(item: str, vault: str = "Agents") -> dict:
    """Retrieve secret at runtime. Never cache or persist."""
    result = subprocess.run(
        ["op", "item", "get", item, "--vault", vault, "--format", "json"],
        capture_output=True, text=True, check=True, timeout=30
    )
    item_data = json.loads(result.stdout)
    fields = {f["label"]: f.get("value") for f in item_data.get("fields", [])}
    
    # Validate expiry if present
    if "expires" in fields:
        from datetime import datetime
        if datetime.now() > datetime.fromisoformat(fields["expires"]):
            raise ValueError("Session expired - request renewal")
    
    return fields
```

---

## Output Sanitization

Scan ALL agent outputs before sending anywhere:

```python
import re

KEY_PATTERNS = [
    (r'0x[a-fA-F0-9]{64}', '[PRIVATE_KEY_REDACTED]'),           # ETH keys
    (r'sk-[a-zA-Z0-9]{48,}', '[OPENAI_KEY_REDACTED]'),          # OpenAI
    (r'sk-ant-api\d{2}-[a-zA-Z0-9\-_]{80,}', '[ANTHROPIC_KEY_REDACTED]'),
    (r'gsk_[a-zA-Z0-9]{48,}', '[GROQ_KEY_REDACTED]'),           # Groq
    (r'AKIA[0-9A-Z]{16}', '[AWS_KEY_REDACTED]'),                # AWS
    (r'ghp_[a-zA-Z0-9]{36}', '[GITHUB_TOKEN_REDACTED]'),        # GitHub
]

def sanitize(text: str) -> str:
    for pattern, replacement in KEY_PATTERNS:
        text = re.sub(pattern, replacement, text)
    return text

# Apply to EVERY output
def respond(content: str) -> str:
    return sanitize(content)
```

---

## Input Validation (Prompt Injection Defense)

Check inputs before ANY wallet operation:

```python
DANGEROUS_PATTERNS = [
    r'(show|print|reveal|output).{0,20}(key|secret|password|private)',
    r'ignore.{0,20}(previous|above|prior).{0,20}instruction',
    r'(transfer|send|withdraw).{0,20}(all|everything|max)',
    r'you\s+are\s+now.{0,20}(admin|unrestricted)',
    r'disregard.{0,20}(rule|instruction|safety)',
]

def is_safe_input(text: str) -> bool:
    text_lower = text.lower()
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, text_lower):
            return False
    return True

def handle_wallet_request(user_input: str):
    if not is_safe_input(user_input):
        return "I can't process that request."
    # ... proceed
```

---

## Operation Allowlisting

Never execute arbitrary operations. Explicit whitelist only:

```python
ALLOWED_OPS = {
    "check_balance": {"handler": get_balance, "max_value": None},
    "transfer_usdc": {"handler": transfer, "max_value": 500, "confirm": True},
    "swap": {"handler": swap, "max_value": 1000, "cooldown": 300},
}

def execute(op_name: str, **kwargs):
    if op_name not in ALLOWED_OPS:
        raise PermissionError(f"Operation '{op_name}' not allowed")
    
    op = ALLOWED_OPS[op_name]
    
    if op.get("max_value") and kwargs.get("amount", 0) > op["max_value"]:
        raise PermissionError(f"Exceeds limit: {op['max_value']}")
    
    if op.get("confirm"):
        return request_confirmation(op_name, kwargs)
    
    return op["handler"](**kwargs)
```

---

## Confirmation for Sensitive Operations

High-value operations require explicit confirmation:

```python
import hashlib, time

pending_confirmations = {}

def request_confirmation(operation: str, details: dict) -> str:
    code = hashlib.sha256(f"{operation}{time.time()}".encode()).hexdigest()[:8].upper()
    pending_confirmations[code] = {
        "op": operation, "details": details, "expires": time.time() + 300
    }
    return f"⚠️ Confirm '{operation}' with code: {code} (expires 5min)"

def confirm(code: str):
    if code not in pending_confirmations:
        return "Invalid code"
    req = pending_confirmations.pop(code)
    if time.time() > req["expires"]:
        return "Code expired"
    return execute_confirmed(req["op"], req["details"])
```

---

## Session Keys (ERC-4337)

Instead of giving agents master keys, issue bounded session keys:

```typescript
// Operator creates session key for agent
const sessionKey = await smartAccount.createSessionKey({
  validUntil: now + 86400,  // 24 hours
  permissions: [
    { target: USDC, method: "transfer", valueLimit: 0, rules: [
      { offset: 36, condition: "LESS_THAN", value: 1000_000000n }  // <1000 USDC
    ]},
    { target: DEX, method: "swap", valueLimit: parseEther("0.1") },
  ],
  spendingLimits: [
    { token: USDC, limit: 5000_000000n, period: 86400 }  // 5k/day
  ]
});

// Store in 1Password for agent retrieval
```

Agent uses session key:
- Cannot exceed limits
- Expires automatically
- Revocable without changing master key
- Scope-restricted to specific contracts/methods

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
    'gsk_[a-zA-Z0-9]{48,}'
    'PRIVATE_KEY=.{20,}'
)

for pattern in "${PATTERNS[@]}"; do
    if git diff --cached | grep -qE "$pattern"; then
        echo "❌ Secret detected: $pattern"
        exit 1
    fi
done
```

---

## .gitignore

```gitignore
.env
.env.*
!.env.example
!.env.tpl
*.pem
*.key
secrets/
keystore/
memory/*.json
session-keys/
```

---

## Common Mistakes

### ❌ Keys in memory files
```markdown
# memory/2026-02-07.md
Private key: 0x9f01dad551039daad...
```
**Fix:** Store reference: `Private key: [1Password: test-wallet]`

### ❌ Keys in error messages
```python
except Exception as e:
    log(f"Failed with key {private_key}: {e}")
```
**Fix:** Never include credentials in error context

### ❌ Keys in .env.example
```
PRIVATE_KEY=sk-ant-api03-real-key...  # "for testing"
```
**Fix:** Use obviously fake: `PRIVATE_KEY=your-key-here`

### ❌ "All" in transfer requests
User says: "Transfer all my USDC"
**Fix:** Block "all/everything/max" patterns, require explicit amounts

---

## Defense Layers

```
USER INPUT
    │
    ▼
┌────────────────────────────┐
│ Layer 1: Input Validation  │  ← Block injection patterns
└────────────────────────────┘
    │
    ▼
┌────────────────────────────┐
│ Layer 2: Op Allowlisting   │  ← Only explicit operations
└────────────────────────────┘
    │
    ▼
┌────────────────────────────┐
│ Layer 3: Confirmation      │  ← Time-limited codes for $$$
└────────────────────────────┘
    │
    ▼
┌────────────────────────────┐
│ Layer 4: Isolated Exec     │  ← Wallet separate from convo
└────────────────────────────┘
    │
    ▼
OUTPUT (sanitized)
```

---

## Checklist

- [ ] Secrets in 1Password/Vault, not files
- [ ] Session keys, not master keys
- [ ] Output sanitization on all responses
- [ ] Input validation before wallet ops
- [ ] Pre-commit hook installed
- [ ] Confirmation flow for transfers
- [ ] Wallet operations isolated from conversation
- [ ] .gitignore covers secrets and memory files
