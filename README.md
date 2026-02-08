# Bagman

Secure key management patterns for AI agents handling wallets, private keys, and secrets.

**Bagman** solves the three critical problems of agentic key management:

1. **Key Loss** — Agents forget credentials between sessions
2. **Accidental Exposure** — Keys leaked to GitHub, logs, or outputs
3. **Prompt Injection** — Malicious prompts extracting secrets

## Quick Start

### For Claude/LLM Agents

Copy `SKILL.md` into your agent's context or skill directory. The skill provides:

- Secure storage patterns (1Password CLI integration)
- Output sanitization (regex patterns to catch keys)
- Input validation (prompt injection defense)
- Session key architecture (bounded delegation)

### For OpenClaw

The skill is available on [ClawHub](https://clawhub.com):

```bash
clawhub install bagman
```

Or copy the `openclaw/` directory to your skills folder.

## Core Principles

```
┌─────────────────────────────────────────────────────┐
│                   AI Agent                          │
├─────────────────────────────────────────────────────┤
│  Session Key (bounded)                              │
│  - Expires after N hours                            │
│  - Max spend per tx/day                             │
│  - Whitelist of contracts                           │
├─────────────────────────────────────────────────────┤
│  Secret Manager (1Password/Vault)                   │
│  - Retrieve at runtime only                         │
│  - Never persist to disk                            │
│  - Audit trail                                      │
├─────────────────────────────────────────────────────┤
│  Smart Account (ERC-4337)                           │
│  - Programmable permissions                         │
│  - Recovery without exposure                        │
└─────────────────────────────────────────────────────┘
```

### The Rules

1. **Never store raw private keys** — Not in config, env, memory, or conversation
2. **Use delegated access** — Session keys with time/value/scope limits
3. **Secrets via secret manager** — 1Password CLI, Vault, AWS Secrets Manager
4. **Sanitize all outputs** — Scan for key patterns before any response
5. **Validate all inputs** — Check for injection attempts before wallet ops

## Documentation

| Document | Description |
|----------|-------------|
| [SKILL.md](SKILL.md) | Main skill file (portable to any Claude agent) |
| [docs/secure-storage.md](docs/secure-storage.md) | 1Password CLI patterns |
| [docs/session-keys.md](docs/session-keys.md) | ERC-4337 delegation patterns (ZeroDev) |
| [docs/erc7710-delegations.md](docs/erc7710-delegations.md) | ERC-7710 delegation patterns (MetaMask) |
| [docs/leak-prevention.md](docs/leak-prevention.md) | Pre-commit hooks, sanitization |
| [docs/prompt-injection.md](docs/prompt-injection.md) | Input validation, allowlisting |

## Examples

### Retrieve Secret at Runtime

```bash
# Never store - retrieve when needed
SESSION_KEY=$(op read "op://Agents/my-agent/session-key")

# Or inject via template (key never touches disk)
op run --env-file=.env.tpl -- python agent.py
```

### Output Sanitization

```python
import re

KEY_PATTERNS = [
    (r'0x[a-fA-F0-9]{64}', '[ETH_KEY_REDACTED]'),
    (r'sk-[a-zA-Z0-9]{48,}', '[OPENAI_KEY_REDACTED]'),
    (r'sk-ant-api\d{2}-[a-zA-Z0-9\-_]{80,}', '[ANTHROPIC_KEY_REDACTED]'),
]

def sanitize(text: str) -> str:
    for pattern, replacement in KEY_PATTERNS:
        text = re.sub(pattern, replacement, text)
    return text

# Apply to EVERY agent output
response = sanitize(response)
```

### Input Validation

```python
DANGEROUS_PATTERNS = [
    r'(show|reveal|output).{0,20}(key|secret|private)',
    r'ignore.{0,20}(previous|system).{0,20}instruction',
    r'(transfer|send).{0,20}(all|everything|max)',
]

def is_safe(text: str) -> bool:
    text_lower = text.lower()
    return not any(re.search(p, text_lower) for p in DANGEROUS_PATTERNS)
```

### Session Keys (ERC-4337)

```typescript
// Operator creates bounded session for agent
const sessionKey = await smartAccount.createSessionKey({
  validUntil: now + 86400,  // 24 hours
  permissions: [
    { target: USDC, method: "transfer", rules: [
      { condition: "LESS_THAN", value: 1000_000000n }  // <1000 USDC
    ]},
  ],
  spendingLimits: [
    { token: USDC, limit: 5000_000000n, period: 86400 }
  ]
});
```

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
│ Layer 2: Op Allowlisting   │  ← Explicit whitelist only
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

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Keys in memory files | Store reference: `[1Password: wallet-name]` |
| Keys in .env.example | Use fake: `PRIVATE_KEY=your-key-here` |
| Keys in error messages | Never include credentials in errors |
| "Transfer all" requests | Block "all/everything/max" patterns |

## Installation

### As Claude Skill

```bash
# Copy SKILL.md to your agent's context
cp SKILL.md /path/to/your/agent/skills/bagman/
```

### As OpenClaw Skill

```bash
# Via ClawHub
clawhub install bagman

# Or manual
cp -r openclaw/ ~/.openclaw/skills/bagman/
```

### Pre-commit Hook

```bash
# Install secret detection hook
cp examples/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit
```

## Requirements

- **1Password CLI** (`op`) — For secure secret retrieval
- **gitleaks** (optional) — Enhanced secret scanning

```bash
brew install 1password-cli gitleaks
```

## Contributing

Issues and PRs welcome. Please ensure any examples use obviously fake keys.

## License

MIT

---

Built by [Number Group](https://numbergroup.xyz) for the agentic economy.
