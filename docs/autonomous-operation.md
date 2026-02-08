# Autonomous vs. Supervised Operation

Bagman supports two modes of operation. **Autonomous-first is recommended** for most agent use cases.

## TL;DR

| Mode | Approvals | Protection | Use Case |
|------|-----------|------------|----------|
| **Autonomous** (recommended) | None within bounds | On-chain delegation caveats | Trading bots, payment agents, DeFi automation |
| **Supervised** | Per-transaction | Confirmation codes | High-risk, human-in-the-loop scenarios |

## Autonomous Mode (Recommended)

Agents operate freely within pre-defined bounds. No per-transaction approval needed.

### How It Works

1. **User creates delegation** with caveats (limits, expiry, allowed contracts)
2. **Agent executes** any operation within those bounds
3. **On-chain enforcement** prevents exceeding limits
4. **No friction** - agent doesn't ask for approval

### Example: Trading Agent

```typescript
// User grants delegation once
const delegation = buildAgentDelegation(agent, user, {
  allowedTargets: [USDC, UNISWAP],
  tokenLimits: [{ token: USDC, maxDecrease: 1000n * 10n**6n }], // $1000 max
  validForSeconds: 24 * 3600,  // 24 hours
  maxCalls: 100,
});

// Agent operates autonomously for 24 hours
// No approval needed per trade
// On-chain caveats enforce the $1000 limit
```

### Python Side

```python
ALLOWED_OPS = {
    "swap": AllowedOperation(
        handler=swap_tokens,
        max_value=Decimal("1000"),      # Software backup
        requires_confirmation=False,     # Autonomous
    ),
    "transfer": AllowedOperation(
        handler=transfer,
        max_value=Decimal("500"),
        requires_confirmation=False,
    ),
}
```

### Protection Layers

Even without per-tx approval, agents are protected by:

1. **Input validation** - Blocks injection attacks
2. **Delegation caveats** - On-chain limits enforced by smart contracts
3. **Software limits** - Backup checks in agent code
4. **Output sanitization** - Prevents key leakage

## Supervised Mode (Opt-In)

For high-risk operations where human oversight is required.

### When to Use

- Emergency withdrawals
- Changing permissions
- Operations exceeding normal bounds
- First-time setup

### Example

```python
ALLOWED_OPS = {
    "emergency_withdraw": AllowedOperation(
        handler=emergency_withdraw,
        requires_confirmation=True,  # Human must approve
    ),
    "revoke_delegation": AllowedOperation(
        handler=revoke_delegation,
        requires_confirmation=True,
    ),
}
```

### Flow

```
Agent: "Emergency withdrawal requested. Confirm with code: A7B3C2D1"
User: "A7B3C2D1"
Agent: *executes withdrawal*
```

## Choosing the Right Mode

### Use Autonomous When:

- ✅ Operations are routine and bounded
- ✅ Delegation caveats can enforce limits
- ✅ Speed matters (trading, payments)
- ✅ Agent needs to operate while user is offline

### Use Supervised When:

- ⚠️ Operation exceeds normal bounds
- ⚠️ Irreversible or high-impact action
- ⚠️ No delegation caveats available
- ⚠️ Regulatory/compliance requires human approval

## Migration Path

Starting supervised and moving to autonomous:

```
Week 1: Supervised mode, confirm all transactions
        → Build trust, verify agent behavior

Week 2: Hybrid mode, confirm only > $100
        → Increase autonomy gradually

Week 3+: Autonomous mode with delegation caveats
        → Full autonomy within bounds
```

## Security Comparison

| Threat | Autonomous | Supervised |
|--------|------------|------------|
| Prompt injection | ✅ Input validation blocks | ✅ Input validation blocks |
| Exceeding limits | ✅ On-chain caveats enforce | ✅ Human reviews each tx |
| Compromised agent | ✅ Bounded by caveats | ✅ Human catches anomalies |
| Key leakage | ✅ Output sanitization | ✅ Output sanitization |
| Speed of attack | ⚠️ Can execute within bounds | ✅ Human can stop |

**Bottom line:** Autonomous mode is secure if delegation caveats are properly configured. The on-chain enforcement is stronger than human review for bounded operations.

## Configuration

### Default: Autonomous

```python
@dataclass
class AllowedOperation:
    name: str
    handler: callable
    max_value: Optional[Decimal] = None
    requires_confirmation: bool = False  # Default autonomous
```

### Opt-in Supervised

```python
AllowedOperation(
    ...,
    requires_confirmation=True,  # Explicit opt-in
)
```
