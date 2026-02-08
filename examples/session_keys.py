"""
Bagman Session Keys (ERC-4337)

Python implementation for creating and managing bounded session keys
for AI agents using smart accounts.

Requires: web3.py, eth-account
"""

from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum
import json
import hashlib

class Condition(Enum):
    EQUAL = "eq"
    LESS_THAN = "lt"
    GREATER_THAN = "gt"
    LESS_OR_EQUAL = "lte"
    GREATER_OR_EQUAL = "gte"

@dataclass
class ParameterRule:
    """Rule for validating call parameters."""
    offset: int  # Byte offset in calldata
    condition: Condition
    value: int
    
    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "condition": self.condition.value,
            "value": str(self.value),
        }

@dataclass
class Permission:
    """Permission for a specific contract/method."""
    target: str  # Contract address
    method: str  # Function selector or name
    value_limit: int = 0  # Max ETH value per call
    rules: List[ParameterRule] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "method": self.method,
            "valueLimit": str(self.value_limit),
            "rules": [r.to_dict() for r in self.rules],
        }

@dataclass
class SpendingLimit:
    """Spending limit for a token over a time period."""
    token: str  # Token address (or "ETH" for native)
    limit: int  # Max amount in smallest unit
    period: int  # Period in seconds
    
    def to_dict(self) -> dict:
        return {
            "token": self.token,
            "limit": str(self.limit),
            "period": self.period,
        }

@dataclass
class SessionKeyConfig:
    """Configuration for a bounded session key."""
    valid_until: int  # Unix timestamp
    valid_after: int = 0  # Unix timestamp (0 = immediately)
    permissions: List[Permission] = field(default_factory=list)
    spending_limits: List[SpendingLimit] = field(default_factory=list)
    
    # Metadata (stored with key, not on-chain)
    name: Optional[str] = None
    agent_id: Optional[str] = None
    operator: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "validUntil": self.valid_until,
            "validAfter": self.valid_after,
            "permissions": [p.to_dict() for p in self.permissions],
            "spendingLimits": [s.to_dict() for s in self.spending_limits],
            "metadata": {
                "name": self.name,
                "agentId": self.agent_id,
                "operator": self.operator,
            }
        }
    
    def is_valid(self) -> bool:
        """Check if session key is currently valid."""
        now = int(datetime.now().timestamp())
        return self.valid_after <= now < self.valid_until


class SessionKeyManager:
    """
    Manage session keys for AI agents.
    
    This is a high-level interface. Actual key creation requires
    integration with a specific smart account implementation
    (e.g., Safe, Kernel, Biconomy).
    """
    
    # Common token addresses (Ethereum mainnet)
    USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    DAI = "0x6B175474E89094C44Da98b954EesdeCD73aE2Dfb"
    WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
    
    @classmethod
    def create_trading_session(
        cls,
        agent_name: str,
        operator_address: str,
        duration_hours: int = 24,
        max_trade_usdc: int = 1000,
        daily_limit_usdc: int = 5000,
        allowed_dex: str = None,
    ) -> SessionKeyConfig:
        """
        Create a session key config for a trading agent.
        
        Args:
            agent_name: Identifier for the agent
            operator_address: Address of the human operator
            duration_hours: How long the key is valid
            max_trade_usdc: Maximum USDC per trade
            daily_limit_usdc: Maximum USDC per day
            allowed_dex: DEX contract address (if restricted)
        """
        now = int(datetime.now().timestamp())
        
        # Convert USDC amounts to 6 decimals
        max_trade_raw = max_trade_usdc * 10**6
        daily_limit_raw = daily_limit_usdc * 10**6
        
        permissions = [
            # Allow USDC transfers up to max_trade
            Permission(
                target=cls.USDC,
                method="transfer",
                rules=[
                    # transfer(address to, uint256 amount)
                    # amount is at offset 36 (4 byte selector + 32 byte address)
                    ParameterRule(offset=36, condition=Condition.LESS_THAN, value=max_trade_raw)
                ]
            ),
            # Allow approvals up to max_trade (not unlimited!)
            Permission(
                target=cls.USDC,
                method="approve",
                rules=[
                    ParameterRule(offset=36, condition=Condition.LESS_OR_EQUAL, value=max_trade_raw)
                ]
            ),
        ]
        
        # If DEX specified, allow swaps
        if allowed_dex:
            permissions.append(
                Permission(
                    target=allowed_dex,
                    method="swap",
                    value_limit=int(0.1 * 10**18),  # Max 0.1 ETH value per swap
                )
            )
        
        spending_limits = [
            SpendingLimit(
                token=cls.USDC,
                limit=daily_limit_raw,
                period=86400,  # 24 hours
            )
        ]
        
        return SessionKeyConfig(
            valid_until=now + (duration_hours * 3600),
            valid_after=now,
            permissions=permissions,
            spending_limits=spending_limits,
            name=f"{agent_name}-trading-session",
            agent_id=agent_name,
            operator=operator_address,
        )
    
    @classmethod
    def create_payment_session(
        cls,
        agent_name: str,
        operator_address: str,
        duration_hours: int = 8,
        max_payment_usdc: int = 100,
        allowed_recipients: List[str] = None,
    ) -> SessionKeyConfig:
        """
        Create a session key config for a payment agent.
        
        Args:
            agent_name: Identifier for the agent
            operator_address: Address of the human operator
            duration_hours: How long the key is valid
            max_payment_usdc: Maximum USDC per payment
            allowed_recipients: Optional list of allowed recipient addresses
        """
        now = int(datetime.now().timestamp())
        max_payment_raw = max_payment_usdc * 10**6
        
        permissions = [
            Permission(
                target=cls.USDC,
                method="transfer",
                rules=[
                    ParameterRule(offset=36, condition=Condition.LESS_OR_EQUAL, value=max_payment_raw)
                ]
            ),
        ]
        
        # Note: Recipient allowlisting would need to be implemented
        # at the smart account level, not just in session key rules
        
        spending_limits = [
            SpendingLimit(
                token=cls.USDC,
                limit=max_payment_raw * 10,  # 10x single payment as daily limit
                period=86400,
            )
        ]
        
        return SessionKeyConfig(
            valid_until=now + (duration_hours * 3600),
            valid_after=now,
            permissions=permissions,
            spending_limits=spending_limits,
            name=f"{agent_name}-payment-session",
            agent_id=agent_name,
            operator=operator_address,
        )
    
    @classmethod
    def validate_operation(
        cls,
        config: SessionKeyConfig,
        target: str,
        method: str,
        value: int = 0,
        calldata: bytes = b'',
    ) -> tuple[bool, str]:
        """
        Validate if an operation is allowed by the session key config.
        
        Returns (is_allowed, reason).
        """
        # Check time validity
        if not config.is_valid():
            return False, "Session key expired or not yet valid"
        
        # Find matching permission
        matching_permission = None
        for perm in config.permissions:
            if perm.target.lower() == target.lower():
                if perm.method == method or perm.method == "*":
                    matching_permission = perm
                    break
        
        if not matching_permission:
            return False, f"No permission for {target}.{method}"
        
        # Check value limit
        if value > matching_permission.value_limit:
            return False, f"Value {value} exceeds limit {matching_permission.value_limit}"
        
        # Check parameter rules
        for rule in matching_permission.rules:
            if len(calldata) > rule.offset + 32:
                param_value = int.from_bytes(calldata[rule.offset:rule.offset+32], 'big')
                
                if rule.condition == Condition.LESS_THAN and not (param_value < rule.value):
                    return False, f"Parameter at offset {rule.offset} fails LT check"
                elif rule.condition == Condition.LESS_OR_EQUAL and not (param_value <= rule.value):
                    return False, f"Parameter at offset {rule.offset} fails LTE check"
                elif rule.condition == Condition.GREATER_THAN and not (param_value > rule.value):
                    return False, f"Parameter at offset {rule.offset} fails GT check"
                elif rule.condition == Condition.EQUAL and not (param_value == rule.value):
                    return False, f"Parameter at offset {rule.offset} fails EQ check"
        
        return True, "OK"
    
    @classmethod
    def export_for_1password(cls, config: SessionKeyConfig, session_key_hex: str) -> dict:
        """
        Export session key config for storage in 1Password.
        
        Returns a dict suitable for `op item create`.
        """
        return {
            "title": config.name,
            "category": "API_CREDENTIAL",
            "fields": [
                {"label": "session-key", "type": "concealed", "value": session_key_hex},
                {"label": "valid-until", "value": datetime.fromtimestamp(config.valid_until).isoformat()},
                {"label": "valid-after", "value": datetime.fromtimestamp(config.valid_after).isoformat()},
                {"label": "agent-id", "value": config.agent_id or ""},
                {"label": "operator", "value": config.operator or ""},
                {"label": "permissions", "value": json.dumps([p.to_dict() for p in config.permissions])},
                {"label": "spending-limits", "value": json.dumps([s.to_dict() for s in config.spending_limits])},
            ]
        }


# Example usage
if __name__ == "__main__":
    print("Session Key Manager Demo\n" + "=" * 50)
    
    # Create a trading session
    trading_config = SessionKeyManager.create_trading_session(
        agent_name="alpha-trader",
        operator_address="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        duration_hours=24,
        max_trade_usdc=1000,
        daily_limit_usdc=5000,
    )
    
    print("\n📊 Trading Session Config:")
    print(f"   Name: {trading_config.name}")
    print(f"   Valid: {trading_config.is_valid()}")
    print(f"   Expires: {datetime.fromtimestamp(trading_config.valid_until)}")
    print(f"   Permissions: {len(trading_config.permissions)}")
    print(f"   Spending Limits: {len(trading_config.spending_limits)}")
    
    # Create a payment session
    payment_config = SessionKeyManager.create_payment_session(
        agent_name="invoice-payer",
        operator_address="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        duration_hours=8,
        max_payment_usdc=100,
    )
    
    print("\n💸 Payment Session Config:")
    print(f"   Name: {payment_config.name}")
    print(f"   Valid: {payment_config.is_valid()}")
    print(f"   Expires: {datetime.fromtimestamp(payment_config.valid_until)}")
    print(f"   Max Payment: $100 USDC")
    
    # Validate operations
    print("\n🔐 Operation Validation:")
    
    # Simulate USDC transfer of $500
    allowed, reason = SessionKeyManager.validate_operation(
        trading_config,
        target=SessionKeyManager.USDC,
        method="transfer",
        calldata=b'\x00' * 36 + (500 * 10**6).to_bytes(32, 'big'),  # $500 USDC
    )
    print(f"   Transfer $500 USDC: {'✅' if allowed else '❌'} {reason}")
    
    # Simulate USDC transfer of $2000 (should fail)
    allowed, reason = SessionKeyManager.validate_operation(
        trading_config,
        target=SessionKeyManager.USDC,
        method="transfer",
        calldata=b'\x00' * 36 + (2000 * 10**6).to_bytes(32, 'big'),  # $2000 USDC
    )
    print(f"   Transfer $2000 USDC: {'✅' if allowed else '❌'} {reason}")
    
    # Export for 1Password
    print("\n📦 1Password Export:")
    export = SessionKeyManager.export_for_1password(
        trading_config,
        session_key_hex="0x" + "a" * 64  # Placeholder
    )
    print(f"   Title: {export['title']}")
    print(f"   Fields: {len(export['fields'])}")
