# ERC-7710 Delegations (MetaMask Smart Accounts Kit)

An alternative to ZeroDev session keys using the **ERC-7710 delegation standard** via MetaMask's Smart Accounts Kit.

## Why ERC-7710?

ERC-7710 is an Ethereum standard for smart contract delegation that offers several advantages over vendor-specific session key implementations:

| Feature | ZeroDev Session Keys | ERC-7710 Delegations |
|---------|---------------------|----------------------|
| **Standard** | Vendor-specific | Ethereum EIP standard |
| **Creation** | On-chain transaction required | Off-chain EIP-712 signature only |
| **Lock-in** | Tied to ZeroDev SDK | Works with any ERC-7710 implementation |
| **Delegate Type** | Must be smart account | EOA or smart account |
| **Sub-delegation** | Limited | Native transitive delegation chains |
| **Caveats** | Permission rules in SDK | Modular on-chain caveat enforcers |
| **Revocation** | On-chain disable | On-chain disable + nonce-based bulk revoke |

### Key Benefits

1. **No Transaction to Create** — Delegations are signed off-chain using EIP-712 typed data. Only redemption requires on-chain execution.

2. **EOA Delegates** — Your agent can be a simple EOA! No need for the delegate to have a smart account.

3. **Modular Caveats** — Restrictions are enforced by smart contracts (caveat enforcers), making them transparent and auditable.

4. **Transitive Delegations** — Agent A can sub-delegate to Agent B, who can sub-delegate to Agent C. Each level can only restrict, never expand authority.

5. **Standard-Based** — Not locked into a single vendor. MetaMask, other wallets, and protocols can all interoperate.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ERC-7710 DELEGATION FRAMEWORK                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────────┐        ┌─────────────────┐                     │
│  │   DELEGATOR     │        │   DELEGATE      │                     │
│  │  Smart Account  │ ─────▶ │  EOA or Smart   │                     │
│  │  (Operator)     │        │  Account (Agent)│                     │
│  └─────────────────┘        └─────────────────┘                     │
│         │                            │                               │
│         │ Signs delegation           │ Redeems delegation           │
│         │ (off-chain EIP-712)        │ (on-chain tx)                │
│         │                            │                               │
│         ▼                            ▼                               │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                   DELEGATION MANAGER                         │    │
│  │  • Validates delegation signatures                           │    │
│  │  • Enforces caveat restrictions (beforeHook/afterHook)       │    │
│  │  • Executes on behalf of delegator                           │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                       │
│                              ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    CAVEAT ENFORCERS                          │    │
│  │  • ValueLteEnforcer (max ETH per call)                       │    │
│  │  • TimestampEnforcer (valid time window)                     │    │
│  │  • AllowedTargetsEnforcer (contract whitelist)               │    │
│  │  • ERC20TransferAmountEnforcer (token spending limit)        │    │
│  │  • LimitedCallsEnforcer (max redemption count)               │    │
│  │  • AllowedMethodsEnforcer (function whitelist)               │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Delegation Chain (Sub-Agents)

```
ROOT DELEGATION
┌─────────────────────────────────────────────────────────────────────┐
│  Operator (Smart Account)                                           │
│  └─▶ Agent A: 1000 USDC, 7 days, [DEX, Lending]                    │
│       │                                                              │
│       │  Agent A can sub-delegate with EQUAL OR LESS authority      │
│       ▼                                                              │
│       Sub-Agent B: 500 USDC, 3 days, [DEX only]                     │
│       │                                                              │
│       │  Sub-Agent B can further restrict                           │
│       ▼                                                              │
│       Sub-Agent C: 100 USDC, 1 day, [specific DEX pool]             │
│                                                                      │
│  Key: Each level can only REDUCE authority, never expand            │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Common Caveat Enforcers

| Enforcer | Purpose | Example |
|----------|---------|---------|
| `timestamp` | Time window for validity | Valid from now until 24h from now |
| `valueLte` | Max native token (ETH) per call | Max 0.1 ETH per transaction |
| `allowedTargets` | Whitelist of callable contracts | Only USDC and Uniswap Router |
| `allowedMethods` | Whitelist of function selectors | Only `transfer` and `approve` |
| `erc20TransferAmount` | Max ERC-20 token transfer | Max 1000 USDC total |
| `erc20PeriodTransfer` | Per-period ERC-20 limit | Max 100 USDC per day |
| `limitedCalls` | Max number of redemptions | Can only be used 5 times |
| `redeemer` | Who can redeem the delegation | Only this specific agent address |
| `nonce` | Bulk revocation via nonce | Revoke all delegations with nonce < N |

---

## Installation

```bash
npm install @metamask/smart-accounts-kit@0.3.0 viem
```

For custom caveat enforcers:

```bash
forge install metamask/delegation-framework@v1.3.0
```

---

## Code Examples

### 1. Create a Delegation with Scope + Caveats

```typescript
import { createDelegation, toMetaMaskSmartAccount, Implementation } from '@metamask/smart-accounts-kit'
import { createPublicClient, http, parseUnits } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'

// Setup
const publicClient = createPublicClient({ chain: sepolia, transport: http() })
const operatorAccount = privateKeyToAccount('0x...')  // Operator's key (hardware wallet recommended)
const agentAddress = '0xAgent...'  // Agent's EOA address

// Create operator's smart account
const delegatorSmartAccount = await toMetaMaskSmartAccount({
  client: publicClient,
  implementation: Implementation.Hybrid,
  deployParams: [operatorAccount.address, [], [], []],
  deploySalt: '0x',
  signer: { account: operatorAccount },
})

// Create delegation with scope and caveats
const now = Math.floor(Date.now() / 1000)
const expiry = now + 86400  // 24 hours

const delegation = createDelegation({
  to: agentAddress,  // Agent's EOA
  from: delegatorSmartAccount.address,
  environment: delegatorSmartAccount.environment,
  // Scope: What authority is being granted
  scope: {
    type: 'erc20TransferAmount',
    tokenAddress: '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238',  // USDC
    maxAmount: parseUnits('1000', 6),  // 1000 USDC total
  },
  // Caveats: Additional restrictions
  caveats: [
    { type: 'timestamp', afterThreshold: now, beforeThreshold: expiry },
    { type: 'limitedCalls', limit: 10 },  // Max 10 transactions
    { type: 'redeemer', redeemers: [agentAddress] },  // Only this agent
  ],
})
```

### 2. Sign the Delegation

```typescript
// Operator signs the delegation (off-chain, no gas!)
const signature = await delegatorSmartAccount.signDelegation({ delegation })
const signedDelegation = { ...delegation, signature }

// Store for agent (in 1Password or secure storage)
const delegationData = {
  delegation: signedDelegation,
  delegatorAddress: delegatorSmartAccount.address,
  environment: delegatorSmartAccount.environment,
  validUntil: expiry,
  scope: 'USDC transfer up to 1000',
}

// Export to JSON for storage
console.log(JSON.stringify(delegationData))
```

### 3. Redeem Delegation (Agent Side)

#### Option A: Agent is an EOA (Simpler)

```typescript
import { createExecution, ExecutionMode } from '@metamask/smart-accounts-kit'
import { DelegationManager } from '@metamask/smart-accounts-kit/contracts'
import { createWalletClient, encodeFunctionData, erc20Abi, http, parseUnits } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'

// Agent retrieves delegation from 1Password
const delegationData = await getFrom1Password('trading-agent-delegation')
const { delegation: signedDelegation, environment } = delegationData

// Validate expiry
if (Date.now() / 1000 > delegationData.validUntil) {
  throw new Error('Delegation expired - request renewal from operator')
}

// Agent's wallet client (EOA)
const agentAccount = privateKeyToAccount('0xAgentPrivateKey...')
const agentWalletClient = createWalletClient({
  account: agentAccount,
  chain: sepolia,
  transport: http(),
})

// Prepare the execution (transfer 100 USDC)
const callData = encodeFunctionData({
  abi: erc20Abi,
  functionName: 'transfer',
  args: ['0xRecipient...', parseUnits('100', 6)],
})

const execution = createExecution({
  target: '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238',  // USDC
  callData,
})

// Encode redemption calldata
const redeemCalldata = DelegationManager.encode.redeemDelegations({
  delegations: [[signedDelegation]],  // Array of delegation chains
  modes: [ExecutionMode.SingleDefault],
  executions: [[execution]],
})

// Execute via EOA transaction to DelegationManager
const txHash = await agentWalletClient.sendTransaction({
  to: environment.DelegationManager,
  data: redeemCalldata,
})

console.log('Transaction:', txHash)
```

#### Option B: Agent is a Smart Account (With Bundler)

```typescript
import { createBundlerClient } from 'viem/account-abstraction'

// Agent's smart account (if needed for sponsored gas)
const agentSmartAccount = await toMetaMaskSmartAccount({
  client: publicClient,
  implementation: Implementation.Hybrid,
  deployParams: [agentAccount.address, [], [], []],
  deploySalt: '0x',
  signer: { account: agentAccount },
})

const bundlerClient = createBundlerClient({
  client: publicClient,
  transport: http('https://bundler-url'),
})

// Send as user operation
const userOpHash = await bundlerClient.sendUserOperation({
  account: agentSmartAccount,
  calls: [{ 
    to: agentSmartAccount.address, 
    data: redeemCalldata 
  }],
})

const receipt = await bundlerClient.waitForUserOperationReceipt({ hash: userOpHash })
console.log('UserOp confirmed:', receipt.receipt.transactionHash)
```

### 4. Sub-Delegation Pattern (Agent → Sub-Agent)

```typescript
// Agent A has delegation from Operator for 1000 USDC
const operatorToAgentA = signedDelegation

// Agent A creates sub-delegation to Agent B with REDUCED scope
const agentAToAgentB = createDelegation({
  to: agentBAddress,
  from: agentAAddress,  // Agent A is the delegator
  environment,
  scope: {
    type: 'erc20TransferAmount',
    tokenAddress: '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238',
    maxAmount: parseUnits('200', 6),  // Only 200 USDC (subset of 1000)
  },
  parentDelegation: operatorToAgentA,  // References parent
  caveats: [
    { type: 'timestamp', afterThreshold: now, beforeThreshold: now + 3600 },  // 1 hour only
    { type: 'limitedCalls', limit: 3 },  // Only 3 uses
    { type: 'allowedTargets', targets: ['0xSpecificDEX...'] },  // Restricted targets
  ],
})

// Agent A signs the sub-delegation
const agentASignature = await agentASmartAccount.signDelegation({ 
  delegation: agentAToAgentB 
})
const signedAgentAToAgentB = { ...agentAToAgentB, signature: agentASignature }

// Agent B redeems by providing the FULL CHAIN
const redeemCalldata = DelegationManager.encode.redeemDelegations({
  delegations: [[operatorToAgentA, signedAgentAToAgentB]],  // Full chain!
  modes: [ExecutionMode.SingleDefault],
  executions: [[execution]],
})
```

---

## Trading Agent Example (ERC-7710 Version)

This mirrors the ZeroDev trading agent example from `session-keys.md`, but uses ERC-7710 delegations:

### Operator Setup (One-Time)

```typescript
import { 
  createDelegation, 
  toMetaMaskSmartAccount, 
  Implementation 
} from '@metamask/smart-accounts-kit'
import { createPublicClient, http, parseUnits, parseEther } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'

// Constants
const USDC = '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238'
const UNISWAP_ROUTER = '0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E'

// Operator's master key (hardware wallet recommended)
const operatorAccount = privateKeyToAccount(process.env.OPERATOR_KEY!)
const agentAddress = '0xAgentEOAAddress...'

const publicClient = createPublicClient({ 
  chain: sepolia, 
  transport: http() 
})

// Create operator's smart account
const operatorSmartAccount = await toMetaMaskSmartAccount({
  client: publicClient,
  implementation: Implementation.Hybrid,
  deployParams: [operatorAccount.address, [], [], []],
  deploySalt: '0x',
  signer: { account: operatorAccount },
})

// Create trading delegation for agent
const now = Math.floor(Date.now() / 1000)
const expiry = now + 86400  // 24 hours

const tradingDelegation = createDelegation({
  to: agentAddress,
  from: operatorSmartAccount.address,
  environment: operatorSmartAccount.environment,
  scope: {
    type: 'functionCall',
    targets: [USDC, UNISWAP_ROUTER],
    selectors: [
      'transfer(address,uint256)',
      'approve(address,uint256)',
      'exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))',
    ],
    valueLte: { maxValue: parseEther('0.1') },  // Max 0.1 ETH per swap
  },
  caveats: [
    { type: 'timestamp', afterThreshold: now, beforeThreshold: expiry },
    { 
      type: 'erc20TransferAmount', 
      tokenAddress: USDC, 
      maxAmount: parseUnits('10000', 6)  // 10k USDC daily limit
    },
    { type: 'limitedCalls', limit: 50 },  // Max 50 trades
    { type: 'redeemer', redeemers: [agentAddress] },
  ],
})

// Sign delegation (no gas!)
const signature = await operatorSmartAccount.signDelegation({ 
  delegation: tradingDelegation 
})
const signedTradingDelegation = { ...tradingDelegation, signature }

// Export for 1Password storage
const exportData = {
  delegation: signedTradingDelegation,
  environment: operatorSmartAccount.environment,
  delegatorAddress: operatorSmartAccount.address,
  validUntil: expiry,
  scope: 'Trading: USDC/ETH swaps, max 10k USDC/day, 50 trades',
  created: new Date().toISOString(),
}

console.log('Store in 1Password:')
console.log(JSON.stringify(exportData, null, 2))
```

### Agent Trading Logic

```typescript
import { createExecution, ExecutionMode } from '@metamask/smart-accounts-kit'
import { DelegationManager } from '@metamask/smart-accounts-kit/contracts'
import { 
  createWalletClient, 
  encodeFunctionData, 
  erc20Abi,
  http, 
  parseUnits 
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'

// Retrieve delegation from 1Password at startup
const tradingCreds = await getFrom1Password('alpha-trader-delegation')

// Validate expiry
if (Date.now() / 1000 > tradingCreds.validUntil) {
  console.error('Delegation expired - notify operator for renewal')
  process.exit(1)
}

const { delegation: signedDelegation, environment } = tradingCreds

// Agent's EOA wallet
const agentAccount = privateKeyToAccount(process.env.AGENT_KEY!)
const agentWallet = createWalletClient({
  account: agentAccount,
  chain: sepolia,
  transport: http(),
})

// Trading function
async function executeSwap(
  tokenIn: `0x${string}`,
  tokenOut: `0x${string}`,
  amountIn: bigint,
  minAmountOut: bigint
) {
  const ROUTER = '0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E'
  
  // Step 1: Approve router (if needed)
  const approveCalldata = encodeFunctionData({
    abi: erc20Abi,
    functionName: 'approve',
    args: [ROUTER, amountIn],
  })
  
  const approveExecution = createExecution({
    target: tokenIn,
    callData: approveCalldata,
  })
  
  // Step 2: Swap
  const swapCalldata = encodeFunctionData({
    abi: [{
      type: 'function',
      name: 'exactInputSingle',
      inputs: [{
        type: 'tuple',
        components: [
          { name: 'tokenIn', type: 'address' },
          { name: 'tokenOut', type: 'address' },
          { name: 'fee', type: 'uint24' },
          { name: 'recipient', type: 'address' },
          { name: 'amountIn', type: 'uint256' },
          { name: 'amountOutMinimum', type: 'uint256' },
          { name: 'sqrtPriceLimitX96', type: 'uint160' },
        ],
      }],
      outputs: [{ type: 'uint256' }],
    }],
    functionName: 'exactInputSingle',
    args: [{
      tokenIn,
      tokenOut,
      fee: 3000,  // 0.3%
      recipient: environment.DelegationManager,  // Delegator receives output
      amountIn,
      amountOutMinimum: minAmountOut,
      sqrtPriceLimitX96: 0n,
    }],
  })
  
  const swapExecution = createExecution({
    target: ROUTER,
    callData: swapCalldata,
  })
  
  // Batch both executions
  const redeemCalldata = DelegationManager.encode.redeemDelegations({
    delegations: [[signedDelegation], [signedDelegation]],
    modes: [ExecutionMode.SingleDefault, ExecutionMode.SingleDefault],
    executions: [[approveExecution], [swapExecution]],
  })
  
  // Execute via agent's EOA
  const txHash = await agentWallet.sendTransaction({
    to: environment.DelegationManager,
    data: redeemCalldata,
  })
  
  console.log(`Swap executed: ${txHash}`)
  return txHash
}

// Example trade
await executeSwap(
  '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238',  // USDC in
  '0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14',  // WETH out
  parseUnits('100', 6),  // 100 USDC
  parseUnits('0.04', 18)  // Min 0.04 WETH
)
```

---

## ZeroDev vs ERC-7710 Comparison

| Aspect | ZeroDev Session Keys | ERC-7710 Delegations |
|--------|---------------------|----------------------|
| **Standard** | Proprietary ZeroDev | Ethereum EIP-7710 |
| **Creation Cost** | Gas for `enableSessionKey` tx | Free (off-chain signature) |
| **Delegate Type** | Smart account only | EOA or smart account |
| **SDK** | `@zerodev/sdk` | `@metamask/smart-accounts-kit` |
| **Permission Model** | Rules embedded in SDK | On-chain caveat enforcers |
| **Sub-delegation** | Not native | Native with `parentDelegation` |
| **Interoperability** | ZeroDev ecosystem | Any ERC-7710 implementation |
| **Revocation** | `disableSessionKey()` on-chain | `disableDelegation()` or nonce bump |
| **MetaMask Integration** | Separate | Native (ERC-7715 for UI) |
| **Gasless Options** | ZeroDev Paymaster | Any ERC-4337 Paymaster |

### When to Use Which

**Choose ZeroDev Session Keys when:**
- Already using ZeroDev Kernel accounts
- Need ZeroDev's paymaster infrastructure
- Simpler setup for single-vendor stack

**Choose ERC-7710 Delegations when:**
- Want vendor-neutral, standard-based approach
- Need EOA delegates (simpler agent architecture)
- Want sub-delegation for agent hierarchies
- Building multi-wallet/multi-vendor systems
- Want free delegation creation (no gas)

---

## Best Practices

### 1. Always Use Caveats

```typescript
// ❌ DANGEROUS - Unlimited authority
const badDelegation = createDelegation({
  to: agentAddress,
  from: delegatorAddress,
  environment,
  scope: { type: 'functionCall', targets: [], selectors: [] },  // No restrictions!
})

// ✅ SAFE - Bounded authority
const goodDelegation = createDelegation({
  to: agentAddress,
  from: delegatorAddress,
  environment,
  scope: {
    type: 'erc20TransferAmount',
    tokenAddress: USDC,
    maxAmount: parseUnits('1000', 6),
  },
  caveats: [
    { type: 'timestamp', afterThreshold: now, beforeThreshold: expiry },
    { type: 'limitedCalls', limit: 10 },
    { type: 'redeemer', redeemers: [agentAddress] },
  ],
})
```

### 2. Short Expiry Windows

```typescript
// Prefer 24-hour delegations over 30-day
const expiry = now + 86400  // 24 hours, not 2592000 (30 days)

// Set up automated renewal
if (delegationData.validUntil - now < 3600) {
  await notifyOperator('Delegation expiring in 1 hour')
}
```

### 3. Store Delegation, Not Secrets

```typescript
// In memory files, store REFERENCE not content
// memory/2025-02-08.md
`Trading delegation stored in 1Password: alpha-trader-delegation
Valid until: 2025-02-09T00:00:00Z
Scope: USDC trades, max 10k/day`

// Never store:
// - Private keys
// - Raw delegation signatures
// - Sensitive parameters
```

### 4. Validate Before Use

```typescript
// Always check expiry at startup and before operations
function validateDelegation(delegationData: DelegationData) {
  const now = Date.now() / 1000
  
  if (now > delegationData.validUntil) {
    throw new Error('Delegation expired')
  }
  
  if (now < delegationData.validAfter) {
    throw new Error('Delegation not yet active')
  }
  
  return true
}
```

---

## Revoking Delegations

### Single Delegation Revocation

```typescript
import { DelegationManager } from '@metamask/smart-accounts-kit/contracts'

// Operator revokes specific delegation
const disableCalldata = DelegationManager.encode.disableDelegation({
  delegation: signedDelegation,
})

await operatorSmartAccount.sendUserOperation({
  calls: [{ to: operatorSmartAccount.address, data: disableCalldata }],
})
```

### Bulk Revocation via Nonce

```typescript
// Create delegations with nonce caveat
const delegation = createDelegation({
  // ... other params
  caveats: [
    { type: 'nonce', nonce: '0x1' },
    // ... other caveats
  ],
})

// Later, invalidate ALL delegations with nonce < 2
await operatorSmartAccount.incrementNonce(2n)
```

---

## Contract Addresses (v1.3.0)

| Contract | Address |
|----------|---------|
| EntryPoint | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` |
| DelegationManager | `0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3` |
| HybridDeleGatorImpl | `0x48dBe696A4D990079e039489bA2053B36E8FFEC4` |
| SimpleFactory | `0x69Aa2f9fe1572F1B640E1bbc512f5c3a734fc77c` |

---

## Resources

- **NPM Package:** `@metamask/smart-accounts-kit@0.3.0`
- **Delegation Framework:** `metamask/delegation-framework@v1.3.0`
- **ERC-7710 Spec:** [https://eips.ethereum.org/EIPS/eip-7710](https://eips.ethereum.org/EIPS/eip-7710)
- **MetaMask Docs:** [https://docs.metamask.io/smart-accounts-kit](https://docs.metamask.io/smart-accounts-kit)
