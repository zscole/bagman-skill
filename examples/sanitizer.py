"""
Bagman Output Sanitizer

Apply to ALL agent outputs before sending to any channel.
Catches keys, secrets, seed phrases, and sensitive patterns.
"""

import re
from typing import List, Tuple, Callable, Union, Set
from functools import lru_cache

class OutputSanitizer:
    """Sanitize agent outputs to prevent secret leakage."""
    
    # BIP-39 word list subset for seed phrase detection (first 100 + common)
    BIP39_WORDS: Set[str] = {
        'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
        'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
        'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual',
        'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
        'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age', 'agent',
        'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album',
        'alcohol', 'alert', 'alien', 'all', 'alley', 'allow', 'almost', 'alone',
        'alpha', 'already', 'also', 'alter', 'always', 'amateur', 'amazing', 'among',
        'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger', 'angle', 'angry',
        'animal', 'ankle', 'announce', 'annual', 'another', 'answer', 'antenna', 'antique',
        # High-frequency seed words
        'brave', 'breeze', 'bridge', 'broken', 'brother', 'bronze', 'bubble', 'bullet',
        'candy', 'captain', 'carbon', 'casino', 'castle', 'catalog', 'caught', 'ceiling',
        'dragon', 'drama', 'dream', 'drink', 'drip', 'drive', 'drum', 'duck',
        'enforce', 'engage', 'engine', 'enrich', 'enroll', 'ensure', 'enter', 'entire',
        'galaxy', 'garage', 'garden', 'garlic', 'garment', 'gather', 'gauge', 'gaze',
        'hidden', 'kidney', 'kitchen', 'kiwi', 'knee', 'knife', 'label', 'labor',
        'wagon', 'wait', 'walk', 'wall', 'walnut', 'want', 'warfare', 'warm',
        'warrior', 'wash', 'wasp', 'waste', 'water', 'wave', 'wealth', 'weapon',
        'whale', 'wheat', 'wheel', 'window', 'wine', 'wing', 'witness', 'wolf',
        'woman', 'wonder', 'wood', 'wool', 'word', 'world', 'worth', 'wrap',
        'wreck', 'wrestle', 'wrist', 'write', 'wrong', 'yellow', 'young', 'youth',
        'zebra', 'zero', 'zone', 'zoo',
    }
    
    SECRET_PATTERNS: List[Tuple[str, Union[str, Callable[[re.Match], str]]]] = [
        # Ethereum private keys (32 bytes = 64 hex chars, with 0x prefix)
        (r'0x[a-fA-F0-9]{64}(?![a-fA-F0-9])', '[PRIVATE_KEY_REDACTED]'),
        
        # Ethereum addresses (20 bytes = 40 hex chars) - truncate, don't hide
        (r'0x[a-fA-F0-9]{40}(?![a-fA-F0-9])', lambda m: f"{m.group()[:6]}...{m.group()[-4:]}"),
        
        # OpenAI keys (multiple formats)
        (r'sk-proj-[a-zA-Z0-9_-]{48,}', '[OPENAI_KEY_REDACTED]'),
        (r'sk-[a-zA-Z0-9]{48,}', '[OPENAI_KEY_REDACTED]'),
        
        # Anthropic keys
        (r'sk-ant-api\d{2}-[a-zA-Z0-9\-_]{80,}', '[ANTHROPIC_KEY_REDACTED]'),
        
        # Groq keys
        (r'gsk_[a-zA-Z0-9]{48,}', '[GROQ_KEY_REDACTED]'),
        
        # AWS keys
        (r'AKIA[0-9A-Z]{16}', '[AWS_ACCESS_KEY_REDACTED]'),
        (r'(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])', '[AWS_SECRET_REDACTED]'),  # AWS secret (40 char base64)
        
        # GitHub tokens
        (r'ghp_[a-zA-Z0-9]{36}', '[GITHUB_PAT_REDACTED]'),
        (r'gho_[a-zA-Z0-9]{36}', '[GITHUB_OAUTH_REDACTED]'),
        (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', '[GITHUB_PAT_REDACTED]'),
        
        # Google Cloud
        (r'AIza[0-9A-Za-z\-_]{35}', '[GOOGLE_API_KEY_REDACTED]'),
        
        # Slack tokens
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', '[SLACK_TOKEN_REDACTED]'),
        
        # Discord tokens
        (r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}', '[DISCORD_TOKEN_REDACTED]'),
        
        # Generic API key patterns
        (r'(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', r'\1=[REDACTED]'),
        
        # Private key in PEM format
        (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', '[PEM_PRIVATE_KEY_REDACTED]'),
        
        # JWT tokens (3 base64 parts)
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', '[JWT_TOKEN_REDACTED]'),
        
        # 1Password references (these are OK but redact the path)
        (r'op://[A-Za-z0-9\-_/]+', '[1PASSWORD_REF]'),
    ]
    
    @classmethod
    def sanitize(cls, text: str) -> str:
        """Remove potential secrets from text."""
        if not text:
            return text
        
        # Apply regex patterns
        for pattern, replacement in cls.SECRET_PATTERNS:
            if callable(replacement):
                text = re.sub(pattern, replacement, text)
            else:
                text = re.sub(pattern, replacement, text)
        
        # Check for seed phrases (12 or 24 word sequences)
        text = cls._redact_seed_phrases(text)
        
        return text
    
    @classmethod
    def _redact_seed_phrases(cls, text: str) -> str:
        """Detect and redact potential BIP-39 seed phrases."""
        words = text.lower().split()
        
        # Look for sequences of 12 or 24 BIP-39 words
        for length in [24, 12]:
            if len(words) < length:
                continue
            
            for i in range(len(words) - length + 1):
                sequence = words[i:i + length]
                bip39_count = sum(1 for w in sequence if w.strip('.,;:!?"\'') in cls.BIP39_WORDS)
                
                # If 80%+ of words are BIP-39, likely a seed phrase
                if bip39_count >= length * 0.8:
                    # Find and replace the sequence in original text
                    original_sequence = ' '.join(text.split()[i:i + length])
                    text = text.replace(original_sequence, f'[SEED_PHRASE_{length}_WORDS_REDACTED]')
                    break
        
        return text
    
    @classmethod
    def contains_secret(cls, text: str) -> bool:
        """Check if text likely contains a secret."""
        if any(re.search(p, text) for p, _ in cls.SECRET_PATTERNS):
            return True
        
        # Check for seed phrase
        words = text.lower().split()
        if len(words) >= 12:
            bip39_count = sum(1 for w in words[:24] if w.strip('.,;:!?"\'') in cls.BIP39_WORDS)
            if bip39_count >= 10:
                return True
        
        return False
    
    @classmethod
    def scan_file(cls, filepath: str) -> List[Tuple[int, str]]:
        """Scan a file for potential secrets. Returns list of (line_number, match)."""
        findings = []
        with open(filepath, 'r', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                if cls.contains_secret(line):
                    findings.append((i, line.strip()[:100]))
        return findings


# Usage example
if __name__ == "__main__":
    test_cases = [
        # Private keys
        "My key is 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        # Addresses (should truncate, not fully redact)
        "Send to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        # OpenAI
        "Using sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz",
        # Anthropic
        "API key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd",
        # Seed phrase (12 words)
        "abandon ability able about above absent absorb abstract absurd abuse access accident",
        # Seed phrase (24 words)
        "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual",
        # JWT
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        # Normal text
        "Normal text without secrets",
        # 1Password reference (OK to show structure)
        "Using op://Agents/my-bot/session-key",
    ]
    
    print("Output Sanitizer Test\n" + "=" * 50)
    for test in test_cases:
        sanitized = OutputSanitizer.sanitize(test)
        changed = "🔒" if test != sanitized else "✅"
        print(f"\n{changed} Original:  {test[:70]}{'...' if len(test) > 70 else ''}")
        print(f"   Sanitized: {sanitized[:70]}{'...' if len(sanitized) > 70 else ''}")
