"""
Bagman Output Sanitizer

Apply to ALL agent outputs before sending to any channel.
"""

import re
from typing import List, Tuple, Callable, Union

class OutputSanitizer:
    """Sanitize agent outputs to prevent secret leakage."""
    
    SECRET_PATTERNS: List[Tuple[str, Union[str, Callable[[re.Match], str]]]] = [
        # Ethereum private keys (full redaction)
        (r'0x[a-fA-F0-9]{64}', '[ETH_KEY_REDACTED]'),
        
        # Ethereum addresses (truncate, don't hide)
        (r'0x[a-fA-F0-9]{40}', lambda m: f"{m.group()[:6]}...{m.group()[-4:]}"),
        
        # OpenAI keys
        (r'sk-proj-[a-zA-Z0-9_-]{48,}', '[OPENAI_KEY_REDACTED]'),
        (r'sk-[a-zA-Z0-9]{48,}', '[OPENAI_KEY_REDACTED]'),
        
        # Anthropic keys
        (r'sk-ant-api\d{2}-[a-zA-Z0-9\-_]{80,}', '[ANTHROPIC_KEY_REDACTED]'),
        
        # Groq keys
        (r'gsk_[a-zA-Z0-9]{48,}', '[GROQ_KEY_REDACTED]'),
        
        # AWS keys
        (r'AKIA[0-9A-Z]{16}', '[AWS_KEY_REDACTED]'),
        
        # GitHub tokens
        (r'ghp_[a-zA-Z0-9]{36}', '[GITHUB_TOKEN_REDACTED]'),
        
        # Generic password/secret assignments
        (r'(password|secret|api_key)\s*[:=]\s*["\']([^"\']{8,})["\']', r'\1=[REDACTED]'),
    ]
    
    @classmethod
    def sanitize(cls, text: str) -> str:
        """Remove potential secrets from text."""
        if not text:
            return text
            
        for pattern, replacement in cls.SECRET_PATTERNS:
            if callable(replacement):
                text = re.sub(pattern, replacement, text)
            else:
                text = re.sub(pattern, replacement, text)
        
        return text
    
    @classmethod
    def contains_secret(cls, text: str) -> bool:
        """Check if text likely contains a secret."""
        return any(re.search(p, text) for p, _ in cls.SECRET_PATTERNS)


# Usage example
if __name__ == "__main__":
    test_cases = [
        "My key is 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "Send to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "Using sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz",
        "API key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd",
        "Normal text without secrets",
    ]
    
    for test in test_cases:
        sanitized = OutputSanitizer.sanitize(test)
        print(f"Original:  {test[:60]}...")
        print(f"Sanitized: {sanitized[:60]}...")
        print()
