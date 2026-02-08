/**
 * Bagman Delegation Framework Integration
 * 
 * Creates bounded delegations for AI agents using MetaMask's Delegation Framework.
 * Combines bagman's input validation with on-chain permission enforcement.
 */

import {
  encodeAbiParameters,
  parseAbiParameters,
  keccak256,
  toHex,
  type Address,
  type Hex,
} from 'viem';

// =============================================================================
// Types
// =============================================================================

export interface Caveat {
  enforcer: Address;
  terms: Hex;
}

export interface Delegation {
  delegate: Address;
  delegator: Address;
  authority: Hex;
  caveats: Caveat[];
  salt: bigint;
  signature: Hex;
}

export interface AgentPermissions {
  /** Contracts the agent can interact with */
  allowedTargets: Address[];
  /** Function selectors the agent can call (optional, defaults to all) */
  allowedMethods?: Hex[];
  /** Max ETH per transaction (in wei) */
  maxEthPerTx?: bigint;
  /** Max ERC20 token decrease per tx */
  tokenLimits?: {
    token: Address;
    maxDecrease: bigint;
  }[];
  /** Delegation validity in seconds (default: 24 hours) */
  validForSeconds?: number;
  /** Max total executions (default: 100) */
  maxCalls?: number;
  /** Enable nonce-based revocation */
  useNonce?: boolean;
}

export interface DelegationConfig {
  delegationManager: Address;
  enforcers: {
    allowedTargets: Address;
    allowedMethods: Address;
    valueLte: Address;
    erc20BalanceChange: Address;
    timestamp: Address;
    limitedCalls: Address;
    nonce: Address;
  };
  chainId: number;
}

// =============================================================================
// Constants
// =============================================================================

// Common function selectors
export const SELECTORS = {
  // ERC20
  transfer: '0xa9059cbb' as Hex,
  approve: '0x095ea7b3' as Hex,
  transferFrom: '0x23b872dd' as Hex,
  // Uniswap V3
  exactInputSingle: '0x414bf389' as Hex,
  exactOutputSingle: '0xdb3e2198' as Hex,
  // Uniswap V2
  swapExactTokensForTokens: '0x38ed1739' as Hex,
  swapTokensForExactTokens: '0x8803dbee' as Hex,
} as const;

// Default configurations
const DEFAULT_VALID_FOR_SECONDS = 24 * 60 * 60; // 24 hours
const DEFAULT_MAX_CALLS = 100;

// =============================================================================
// Caveat Builders
// =============================================================================

/**
 * Build AllowedTargetsEnforcer caveat
 */
export function buildAllowedTargetsCaveat(
  enforcer: Address,
  targets: Address[]
): Caveat {
  return {
    enforcer,
    terms: encodeAbiParameters(
      parseAbiParameters('address[]'),
      [targets]
    ),
  };
}

/**
 * Build AllowedMethodsEnforcer caveat
 */
export function buildAllowedMethodsCaveat(
  enforcer: Address,
  selectors: Hex[]
): Caveat {
  return {
    enforcer,
    terms: encodeAbiParameters(
      parseAbiParameters('bytes4[]'),
      [selectors]
    ),
  };
}

/**
 * Build ValueLteEnforcer caveat (max ETH per tx)
 */
export function buildValueLteCaveat(
  enforcer: Address,
  maxWei: bigint
): Caveat {
  return {
    enforcer,
    terms: encodeAbiParameters(
      parseAbiParameters('uint256'),
      [maxWei]
    ),
  };
}

/**
 * Build ERC20BalanceChangeEnforcer caveat
 */
export function buildERC20BalanceChangeCaveat(
  enforcer: Address,
  token: Address,
  maxDecrease: bigint,
  recipient?: Address
): Caveat {
  // terms: (address token, address recipient, uint256 amount, bool isIncrease)
  return {
    enforcer,
    terms: encodeAbiParameters(
      parseAbiParameters('address, address, uint256, bool'),
      [token, recipient ?? '0x0000000000000000000000000000000000000000', maxDecrease, false]
    ),
  };
}

/**
 * Build TimestampEnforcer caveat (expiry)
 */
export function buildTimestampCaveat(
  enforcer: Address,
  validUntilTimestamp: bigint
): Caveat {
  // terms: (uint128 afterTimestamp, uint128 beforeTimestamp)
  return {
    enforcer,
    terms: encodeAbiParameters(
      parseAbiParameters('uint128, uint128'),
      [0n, validUntilTimestamp]
    ),
  };
}

/**
 * Build LimitedCallsEnforcer caveat
 */
export function buildLimitedCallsCaveat(
  enforcer: Address,
  maxCalls: number
): Caveat {
  return {
    enforcer,
    terms: encodeAbiParameters(
      parseAbiParameters('uint256'),
      [BigInt(maxCalls)]
    ),
  };
}

/**
 * Build NonceEnforcer caveat (for revocation)
 */
export function buildNonceCaveat(
  enforcer: Address,
  nonce: bigint
): Caveat {
  return {
    enforcer,
    terms: encodeAbiParameters(
      parseAbiParameters('uint256'),
      [nonce]
    ),
  };
}

// =============================================================================
// Delegation Builder
// =============================================================================

/**
 * Build a complete delegation with caveats for an AI agent.
 * 
 * @example
 * ```ts
 * const delegation = buildAgentDelegation(
 *   agentAddress,
 *   userAddress,
 *   {
 *     allowedTargets: [USDC_ADDRESS, UNISWAP_ROUTER],
 *     allowedMethods: [SELECTORS.transfer, SELECTORS.exactInputSingle],
 *     maxEthPerTx: parseEther('0.1'),
 *     tokenLimits: [{ token: USDC_ADDRESS, maxDecrease: 1000n * 10n**6n }],
 *     validForSeconds: 24 * 3600,
 *     maxCalls: 50,
 *   },
 *   config
 * );
 * ```
 */
export function buildAgentDelegation(
  agentAddress: Address,
  delegatorAddress: Address,
  permissions: AgentPermissions,
  config: DelegationConfig
): Omit<Delegation, 'signature'> {
  const caveats: Caveat[] = [];
  const now = BigInt(Math.floor(Date.now() / 1000));
  
  // 1. REQUIRED: Allowed targets
  if (permissions.allowedTargets.length === 0) {
    throw new Error('allowedTargets is required and cannot be empty');
  }
  caveats.push(
    buildAllowedTargetsCaveat(config.enforcers.allowedTargets, permissions.allowedTargets)
  );
  
  // 2. Optional: Allowed methods
  if (permissions.allowedMethods && permissions.allowedMethods.length > 0) {
    caveats.push(
      buildAllowedMethodsCaveat(config.enforcers.allowedMethods, permissions.allowedMethods)
    );
  }
  
  // 3. Optional: Max ETH per tx
  if (permissions.maxEthPerTx !== undefined) {
    caveats.push(
      buildValueLteCaveat(config.enforcers.valueLte, permissions.maxEthPerTx)
    );
  }
  
  // 4. Optional: Token limits
  if (permissions.tokenLimits) {
    for (const limit of permissions.tokenLimits) {
      caveats.push(
        buildERC20BalanceChangeCaveat(
          config.enforcers.erc20BalanceChange,
          limit.token,
          limit.maxDecrease
        )
      );
    }
  }
  
  // 5. REQUIRED: Expiry
  const validFor = permissions.validForSeconds ?? DEFAULT_VALID_FOR_SECONDS;
  caveats.push(
    buildTimestampCaveat(config.enforcers.timestamp, now + BigInt(validFor))
  );
  
  // 6. REQUIRED: Max calls
  const maxCalls = permissions.maxCalls ?? DEFAULT_MAX_CALLS;
  caveats.push(
    buildLimitedCallsCaveat(config.enforcers.limitedCalls, maxCalls)
  );
  
  // 7. Optional: Nonce for revocation
  if (permissions.useNonce) {
    // Start at nonce 0; user increments to revoke
    caveats.push(
      buildNonceCaveat(config.enforcers.nonce, 0n)
    );
  }
  
  return {
    delegate: agentAddress,
    delegator: delegatorAddress,
    authority: '0x0000000000000000000000000000000000000000000000000000000000000000' as Hex,
    caveats,
    salt: BigInt(Date.now()),
    signature: '0x' as Hex, // To be signed by delegator
  };
}

// =============================================================================
// EIP-712 Signing
// =============================================================================

export const DELEGATION_TYPES = {
  Delegation: [
    { name: 'delegate', type: 'address' },
    { name: 'delegator', type: 'address' },
    { name: 'authority', type: 'bytes32' },
    { name: 'caveats', type: 'Caveat[]' },
    { name: 'salt', type: 'uint256' },
  ],
  Caveat: [
    { name: 'enforcer', type: 'address' },
    { name: 'terms', type: 'bytes' },
  ],
} as const;

export function getDelegationDomain(config: DelegationConfig) {
  return {
    name: 'DelegationManager',
    version: '1',
    chainId: config.chainId,
    verifyingContract: config.delegationManager,
  };
}

/**
 * Get the typed data for signing a delegation.
 * Use with wallet.signTypedData() or similar.
 */
export function getDelegationTypedData(
  delegation: Omit<Delegation, 'signature'>,
  config: DelegationConfig
) {
  return {
    domain: getDelegationDomain(config),
    types: DELEGATION_TYPES,
    primaryType: 'Delegation' as const,
    message: {
      delegate: delegation.delegate,
      delegator: delegation.delegator,
      authority: delegation.authority,
      caveats: delegation.caveats,
      salt: delegation.salt,
    },
  };
}

// =============================================================================
// Preset Configurations
// =============================================================================

/**
 * Trading agent preset: Can swap tokens on DEX with limits
 */
export function tradingAgentPreset(
  tokens: Address[],
  dexRouter: Address,
  maxUsdPerTx: bigint,
  stablecoin: Address
): AgentPermissions {
  return {
    allowedTargets: [dexRouter, ...tokens],
    allowedMethods: [
      SELECTORS.approve,
      SELECTORS.exactInputSingle,
      SELECTORS.exactOutputSingle,
      SELECTORS.swapExactTokensForTokens,
    ],
    maxEthPerTx: 0n, // No direct ETH transfers
    tokenLimits: [{ token: stablecoin, maxDecrease: maxUsdPerTx }],
    validForSeconds: 24 * 3600,
    maxCalls: 50,
    useNonce: true,
  };
}

/**
 * Payment agent preset: Can send payments to whitelisted addresses
 */
export function paymentAgentPreset(
  paymentToken: Address,
  recipients: Address[],
  maxAmountPerTx: bigint
): AgentPermissions {
  return {
    allowedTargets: [paymentToken],
    allowedMethods: [SELECTORS.transfer],
    maxEthPerTx: 0n,
    tokenLimits: [{ token: paymentToken, maxDecrease: maxAmountPerTx }],
    validForSeconds: 8 * 3600, // 8 hours
    maxCalls: 20,
    useNonce: true,
  };
}

/**
 * Read-only agent preset: Can only call view functions (no state changes)
 * Note: This requires a custom ViewOnlyEnforcer
 */
export function readOnlyAgentPreset(
  contracts: Address[]
): AgentPermissions {
  return {
    allowedTargets: contracts,
    maxEthPerTx: 0n,
    validForSeconds: 7 * 24 * 3600, // 1 week (safe for read-only)
    maxCalls: 1000,
    useNonce: false,
  };
}

// =============================================================================
// Validation (combines with bagman)
// =============================================================================

/**
 * Validate that permissions are safe for an AI agent.
 * Use this before creating a delegation to catch dangerous configurations.
 */
export function validatePermissions(permissions: AgentPermissions): {
  valid: boolean;
  warnings: string[];
  errors: string[];
} {
  const warnings: string[] = [];
  const errors: string[] = [];
  
  // Check for empty targets (dangerous!)
  if (!permissions.allowedTargets || permissions.allowedTargets.length === 0) {
    errors.push('allowedTargets is required - agent would have no restrictions');
  }
  
  // Warn if no method restrictions
  if (!permissions.allowedMethods || permissions.allowedMethods.length === 0) {
    warnings.push('No allowedMethods specified - agent can call any function on allowed targets');
  }
  
  // Warn if expiry is long
  const validFor = permissions.validForSeconds ?? DEFAULT_VALID_FOR_SECONDS;
  if (validFor > 7 * 24 * 3600) {
    warnings.push(`Delegation valid for ${Math.floor(validFor / 3600 / 24)} days - consider shorter expiry`);
  }
  
  // Warn if max calls is high
  const maxCalls = permissions.maxCalls ?? DEFAULT_MAX_CALLS;
  if (maxCalls > 500) {
    warnings.push(`Max calls is ${maxCalls} - consider lower limit for autonomous agents`);
  }
  
  // Check for unlimited ETH
  if (permissions.maxEthPerTx === undefined) {
    warnings.push('No maxEthPerTx specified - agent can send unlimited ETH per transaction');
  }
  
  // Check for missing token limits
  if (!permissions.tokenLimits || permissions.tokenLimits.length === 0) {
    warnings.push('No token limits specified - agent can move unlimited tokens');
  }
  
  // Recommend nonce for revocability
  if (!permissions.useNonce) {
    warnings.push('useNonce is false - delegation cannot be easily revoked');
  }
  
  return {
    valid: errors.length === 0,
    warnings,
    errors,
  };
}

// =============================================================================
// Export
// =============================================================================

export default {
  // Builders
  buildAgentDelegation,
  buildAllowedTargetsCaveat,
  buildAllowedMethodsCaveat,
  buildValueLteCaveat,
  buildERC20BalanceChangeCaveat,
  buildTimestampCaveat,
  buildLimitedCallsCaveat,
  buildNonceCaveat,
  
  // Signing helpers
  getDelegationTypedData,
  getDelegationDomain,
  DELEGATION_TYPES,
  
  // Presets
  tradingAgentPreset,
  paymentAgentPreset,
  readOnlyAgentPreset,
  
  // Validation
  validatePermissions,
  
  // Constants
  SELECTORS,
};
