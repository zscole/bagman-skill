/**
 * Bagman Delegation Integration Tests
 * 
 * Tests the delegation building and validation logic.
 * Does NOT require deployed contracts (unit tests only).
 */

import {
  buildAgentDelegation,
  buildAllowedTargetsCaveat,
  buildAllowedMethodsCaveat,
  buildValueLteCaveat,
  buildERC20BalanceChangeCaveat,
  buildTimestampCaveat,
  buildLimitedCallsCaveat,
  buildNonceCaveat,
  validatePermissions,
  tradingAgentPreset,
  paymentAgentPreset,
  readOnlyAgentPreset,
  getDelegationTypedData,
  SELECTORS,
  type AgentPermissions,
  type DelegationConfig,
} from './delegation_integration';

// =============================================================================
// Test Config
// =============================================================================

const TEST_CONFIG: DelegationConfig = {
  delegationManager: '0x1234567890123456789012345678901234567890',
  enforcers: {
    allowedTargets: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    allowedMethods: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    valueLte: '0xcccccccccccccccccccccccccccccccccccccccc',
    erc20BalanceChange: '0xdddddddddddddddddddddddddddddddddddddddd',
    timestamp: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    limitedCalls: '0xffffffffffffffffffffffffffffffffffffffff',
    nonce: '0x1111111111111111111111111111111111111111',
  },
  chainId: 1,
};

const AGENT_ADDRESS = '0x2222222222222222222222222222222222222222' as const;
const USER_ADDRESS = '0x3333333333333333333333333333333333333333' as const;
const USDC_ADDRESS = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' as const;
const UNISWAP_ROUTER = '0xe592427a0aece92de3edee1f18e0157c05861564' as const;

// =============================================================================
// Test Utilities
// =============================================================================

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void) {
  try {
    fn();
    console.log(`✅ ${name}`);
    passed++;
  } catch (e) {
    console.log(`❌ ${name}`);
    console.log(`   Error: ${e instanceof Error ? e.message : e}`);
    failed++;
  }
}

function assert(condition: boolean, message: string) {
  if (!condition) throw new Error(message);
}

function assertEqual<T>(actual: T, expected: T, message: string) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${expected}, got ${actual}`);
  }
}

// =============================================================================
// Caveat Builder Tests
// =============================================================================

console.log('\n=== Caveat Builder Tests ===\n');

test('buildAllowedTargetsCaveat creates valid caveat', () => {
  const caveat = buildAllowedTargetsCaveat(
    TEST_CONFIG.enforcers.allowedTargets,
    [USDC_ADDRESS, UNISWAP_ROUTER]
  );
  assert(caveat.enforcer === TEST_CONFIG.enforcers.allowedTargets, 'Wrong enforcer');
  assert(caveat.terms.startsWith('0x'), 'Terms should be hex');
  assert(caveat.terms.length > 10, 'Terms too short');
});

test('buildAllowedMethodsCaveat creates valid caveat', () => {
  const caveat = buildAllowedMethodsCaveat(
    TEST_CONFIG.enforcers.allowedMethods,
    [SELECTORS.transfer, SELECTORS.approve]
  );
  assert(caveat.enforcer === TEST_CONFIG.enforcers.allowedMethods, 'Wrong enforcer');
  assert(caveat.terms.includes('a9059cbb'), 'Should contain transfer selector');
});

test('buildValueLteCaveat creates valid caveat', () => {
  const caveat = buildValueLteCaveat(
    TEST_CONFIG.enforcers.valueLte,
    BigInt(1e18) // 1 ETH
  );
  assert(caveat.enforcer === TEST_CONFIG.enforcers.valueLte, 'Wrong enforcer');
  assert(caveat.terms.length === 66, 'uint256 should be 32 bytes + 0x');
});

test('buildERC20BalanceChangeCaveat creates valid caveat', () => {
  const caveat = buildERC20BalanceChangeCaveat(
    TEST_CONFIG.enforcers.erc20BalanceChange,
    USDC_ADDRESS,
    BigInt(1000e6) // 1000 USDC
  );
  assert(caveat.enforcer === TEST_CONFIG.enforcers.erc20BalanceChange, 'Wrong enforcer');
  assert(caveat.terms.length > 100, 'Terms too short for 4 params');
});

test('buildTimestampCaveat creates valid caveat', () => {
  const expiry = BigInt(Math.floor(Date.now() / 1000) + 86400);
  const caveat = buildTimestampCaveat(
    TEST_CONFIG.enforcers.timestamp,
    expiry
  );
  assert(caveat.enforcer === TEST_CONFIG.enforcers.timestamp, 'Wrong enforcer');
});

test('buildLimitedCallsCaveat creates valid caveat', () => {
  const caveat = buildLimitedCallsCaveat(
    TEST_CONFIG.enforcers.limitedCalls,
    50
  );
  assert(caveat.enforcer === TEST_CONFIG.enforcers.limitedCalls, 'Wrong enforcer');
});

test('buildNonceCaveat creates valid caveat', () => {
  const caveat = buildNonceCaveat(
    TEST_CONFIG.enforcers.nonce,
    0n
  );
  assert(caveat.enforcer === TEST_CONFIG.enforcers.nonce, 'Wrong enforcer');
});

// =============================================================================
// Delegation Builder Tests
// =============================================================================

console.log('\n=== Delegation Builder Tests ===\n');

test('buildAgentDelegation creates delegation with required caveats', () => {
  const delegation = buildAgentDelegation(
    AGENT_ADDRESS,
    USER_ADDRESS,
    {
      allowedTargets: [USDC_ADDRESS],
      validForSeconds: 3600,
      maxCalls: 10,
    },
    TEST_CONFIG
  );
  
  assert(delegation.delegate === AGENT_ADDRESS, 'Wrong delegate');
  assert(delegation.delegator === USER_ADDRESS, 'Wrong delegator');
  assert(delegation.caveats.length >= 3, 'Should have at least 3 caveats');
  assert(delegation.salt > 0n, 'Salt should be set');
});

test('buildAgentDelegation throws on empty allowedTargets', () => {
  let threw = false;
  try {
    buildAgentDelegation(
      AGENT_ADDRESS,
      USER_ADDRESS,
      { allowedTargets: [] },
      TEST_CONFIG
    );
  } catch (e) {
    threw = true;
  }
  assert(threw, 'Should throw on empty allowedTargets');
});

test('buildAgentDelegation includes optional caveats when specified', () => {
  const delegation = buildAgentDelegation(
    AGENT_ADDRESS,
    USER_ADDRESS,
    {
      allowedTargets: [USDC_ADDRESS, UNISWAP_ROUTER],
      allowedMethods: [SELECTORS.transfer],
      maxEthPerTx: BigInt(1e17), // 0.1 ETH
      tokenLimits: [{ token: USDC_ADDRESS, maxDecrease: BigInt(500e6) }],
      validForSeconds: 86400,
      maxCalls: 50,
      useNonce: true,
    },
    TEST_CONFIG
  );
  
  // AllowedTargets + AllowedMethods + ValueLte + ERC20BalanceChange + Timestamp + LimitedCalls + Nonce
  assertEqual(delegation.caveats.length, 7, 'Caveat count');
});

// =============================================================================
// Preset Tests
// =============================================================================

console.log('\n=== Preset Tests ===\n');

test('tradingAgentPreset creates valid permissions', () => {
  const permissions = tradingAgentPreset(
    [USDC_ADDRESS],
    UNISWAP_ROUTER,
    BigInt(1000e6),
    USDC_ADDRESS
  );
  
  assert(permissions.allowedTargets.length >= 2, 'Should include DEX and tokens');
  assert(permissions.allowedMethods!.length > 0, 'Should have method restrictions');
  assert(permissions.useNonce === true, 'Should use nonce');
});

test('paymentAgentPreset creates valid permissions', () => {
  const permissions = paymentAgentPreset(
    USDC_ADDRESS,
    [USER_ADDRESS],
    BigInt(100e6)
  );
  
  assert(permissions.allowedTargets.length === 1, 'Should only include payment token');
  assert(permissions.allowedMethods!.includes(SELECTORS.transfer), 'Should allow transfer');
  assert(permissions.maxCalls === 20, 'Should limit calls');
});

test('readOnlyAgentPreset creates valid permissions', () => {
  const permissions = readOnlyAgentPreset([USDC_ADDRESS, UNISWAP_ROUTER]);
  
  assert(permissions.allowedTargets.length === 2, 'Should include specified contracts');
  assert(permissions.maxEthPerTx === 0n, 'Should not allow ETH transfers');
  assert(permissions.maxCalls === 1000, 'Should allow many reads');
});

// =============================================================================
// Validation Tests
// =============================================================================

console.log('\n=== Validation Tests ===\n');

test('validatePermissions passes valid config', () => {
  const result = validatePermissions({
    allowedTargets: [USDC_ADDRESS],
    allowedMethods: [SELECTORS.transfer],
    maxEthPerTx: BigInt(1e17),
    tokenLimits: [{ token: USDC_ADDRESS, maxDecrease: BigInt(500e6) }],
    validForSeconds: 86400,
    maxCalls: 50,
    useNonce: true,
  });
  
  assert(result.valid === true, 'Should be valid');
  assertEqual(result.errors.length, 0, 'Error count');
});

test('validatePermissions rejects empty allowedTargets', () => {
  const result = validatePermissions({
    allowedTargets: [],
  });
  
  assert(result.valid === false, 'Should be invalid');
  assert(result.errors.length > 0, 'Should have errors');
});

test('validatePermissions warns on missing restrictions', () => {
  const result = validatePermissions({
    allowedTargets: [USDC_ADDRESS],
    // Missing: allowedMethods, maxEthPerTx, tokenLimits, useNonce
  });
  
  assert(result.valid === true, 'Should still be valid');
  assert(result.warnings.length >= 3, 'Should have multiple warnings');
});

test('validatePermissions warns on long expiry', () => {
  const result = validatePermissions({
    allowedTargets: [USDC_ADDRESS],
    validForSeconds: 30 * 24 * 3600, // 30 days
  });
  
  const hasExpiryWarning = result.warnings.some(w => w.includes('days'));
  assert(hasExpiryWarning, 'Should warn about long expiry');
});

// =============================================================================
// EIP-712 Tests
// =============================================================================

console.log('\n=== EIP-712 Tests ===\n');

test('getDelegationTypedData returns valid structure', () => {
  const delegation = buildAgentDelegation(
    AGENT_ADDRESS,
    USER_ADDRESS,
    { allowedTargets: [USDC_ADDRESS] },
    TEST_CONFIG
  );
  
  const typedData = getDelegationTypedData(delegation, TEST_CONFIG);
  
  assert(typedData.domain.name === 'DelegationManager', 'Wrong domain name');
  assert(typedData.domain.chainId === 1, 'Wrong chain ID');
  assert(typedData.primaryType === 'Delegation', 'Wrong primary type');
  assert(typedData.types.Delegation.length === 5, 'Wrong type fields');
  assert(typedData.message.delegate === AGENT_ADDRESS, 'Wrong message delegate');
});

// =============================================================================
// Summary
// =============================================================================

console.log('\n' + '='.repeat(50));
console.log(`DELEGATION INTEGRATION TESTS`);
console.log('='.repeat(50));
console.log(`✅ Passed: ${passed}`);
console.log(`❌ Failed: ${failed}`);
console.log('='.repeat(50));

if (failed > 0) {
  process.exit(1);
}
