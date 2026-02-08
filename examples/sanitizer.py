"""
Bagman Output Sanitizer (v2)

Apply to ALL agent outputs before sending to any channel.
Catches keys, secrets, seed phrases, and sensitive patterns.

Improvements over v1:
- Full BIP-39 wordlist (2048 words)
- Fixed AWS secret pattern (was too broad)
- Added split-key detection
- Better hex key detection
"""

import re
import os
from typing import List, Tuple, Callable, Union, Set
from pathlib import Path


class OutputSanitizer:
    """Sanitize agent outputs to prevent secret leakage."""
    
    # Load full BIP-39 wordlist (2048 words)
    _BIP39_WORDS: Set[str] = None
    
    @classmethod
    def _load_bip39_words(cls) -> Set[str]:
        if cls._BIP39_WORDS is not None:
            return cls._BIP39_WORDS
        
        wordlist_path = Path(__file__).parent / "bip39_wordlist.txt"
        if wordlist_path.exists():
            with open(wordlist_path) as f:
                cls._BIP39_WORDS = {line.strip().lower() for line in f if line.strip()}
        else:
            # Fallback to embedded subset if file missing
            cls._BIP39_WORDS = {
                'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 
                'abstract', 'absurd', 'abuse', 'access', 'accident', 'account', 'accuse',
                'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act', 'action',
                'actor', 'actress', 'actual', 'adapt', 'add', 'addict', 'address',
                'adjust', 'admit', 'adult', 'advance', 'advice', 'aerobic', 'affair',
                'afford', 'afraid', 'again', 'age', 'agent', 'agree', 'ahead', 'aim',
                'air', 'airport', 'aisle', 'alarm', 'album', 'alcohol', 'alert',
                'alien', 'all', 'alley', 'allow', 'almost', 'alone', 'alpha', 'already',
                'also', 'alter', 'always', 'amateur', 'amazing', 'among', 'amount',
                'zoo', 'zone', 'zero', 'zebra', 'youth', 'young', 'yellow', 'wrong',
                'write', 'wrist', 'wrestle', 'wreck', 'wrap', 'worth', 'world', 'word',
            }
        return cls._BIP39_WORDS
    
    SECRET_PATTERNS: List[Tuple[str, Union[str, Callable[[re.Match], str]]]] = [
        # Ethereum private keys (32 bytes = 64 hex chars, with 0x prefix)
        (r'0x[a-fA-F0-9]{64}(?![a-fA-F0-9])', '[PRIVATE_KEY_REDACTED]'),
        
        # Raw hex that looks like a private key (64 hex without 0x prefix, word boundary)
        (r'(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])', '[HEX_KEY_REDACTED]'),
        
        # Split key detection (32 hex chars that could be half a key)
        (r'(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])', '[PARTIAL_KEY_REDACTED]'),
        
        # Ethereum addresses (20 bytes = 40 hex chars) - truncate, don't hide
        (r'0x[a-fA-F0-9]{40}(?![a-fA-F0-9])', lambda m: f"{m.group()[:6]}...{m.group()[-4:]}"),
        
        # OpenAI keys (multiple formats)
        (r'sk-proj-[a-zA-Z0-9_-]{20,}', '[OPENAI_KEY_REDACTED]'),
        (r'sk-[a-zA-Z0-9]{32,}', '[OPENAI_KEY_REDACTED]'),
        
        # Anthropic keys
        (r'sk-ant-api\d{2}-[a-zA-Z0-9\-_]{40,}', '[ANTHROPIC_KEY_REDACTED]'),
        
        # Groq keys
        (r'gsk_[a-zA-Z0-9]{20,}', '[GROQ_KEY_REDACTED]'),
        
        # AWS Access Key ID (very specific format)
        (r'AKIA[0-9A-Z]{16}', '[AWS_ACCESS_KEY_REDACTED]'),
        
        # AWS Secret Key (40 chars, but require context to reduce false positives)
        (r'(?i)(?:aws|secret|key|credential)[_\s]*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', '[AWS_SECRET_REDACTED]'),
        
        # GitHub tokens
        (r'ghp_[a-zA-Z0-9]{36}', '[GITHUB_PAT_REDACTED]'),
        (r'gho_[a-zA-Z0-9]{36}', '[GITHUB_OAUTH_REDACTED]'),
        (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', '[GITHUB_PAT_REDACTED]'),
        (r'ghr_[a-zA-Z0-9]{36}', '[GITHUB_REFRESH_REDACTED]'),
        
        # Google Cloud
        (r'AIza[0-9A-Za-z\-_]{35}', '[GOOGLE_API_KEY_REDACTED]'),
        
        # Slack tokens
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*', '[SLACK_TOKEN_REDACTED]'),
        
        # Discord tokens (Bot and user)
        (r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}', '[DISCORD_TOKEN_REDACTED]'),
        
        # Telegram bot tokens (format: botid:secret)
        (r'\d{8,12}:[A-Za-z0-9_-]{30,}', '[TELEGRAM_TOKEN_REDACTED]'),
        
        # Generic API key patterns (with context)
        (r'(?i)(api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', r'\1=[REDACTED]'),
        
        # Private key in PEM format
        (r'-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', '[PEM_PRIVATE_KEY_REDACTED]'),
        
        # JWT tokens (3 base64 parts)
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', '[JWT_TOKEN_REDACTED]'),
        
        # 1Password references (safe to show structure, redact specifics)
        (r'op://[A-Za-z0-9\-_/]+', '[1PASSWORD_REF]'),
        
        # Infura/Alchemy project IDs
        (r'(?i)(infura|alchemy)[_\s]*(?:project[_\s]*)?(?:id|key|secret)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', r'\1=[REDACTED]'),
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
        bip39_words = cls._load_bip39_words()
        words = text.split()
        
        if len(words) < 12:
            return text
        
        # Look for sequences of 12 or 24 BIP-39 words
        for length in [24, 12]:
            if len(words) < length:
                continue
            
            for i in range(len(words) - length + 1):
                sequence = words[i:i + length]
                # Clean punctuation from words for matching
                cleaned = [w.strip('.,;:!?"\'-()[]{}').lower() for w in sequence]
                bip39_count = sum(1 for w in cleaned if w in bip39_words)
                
                # If 90%+ of words are BIP-39, likely a seed phrase
                if bip39_count >= length * 0.9:
                    original_sequence = ' '.join(words[i:i + length])
                    text = text.replace(original_sequence, f'[SEED_PHRASE_{length}_WORDS_REDACTED]')
                    return cls._redact_seed_phrases(text)  # Recurse for multiple phrases
        
        return text
    
    @classmethod
    def contains_secret(cls, text: str) -> Tuple[bool, str]:
        """Check if text likely contains a secret. Returns (bool, reason)."""
        if not text:
            return False, ""
        
        for pattern, _ in cls.SECRET_PATTERNS:
            match = re.search(pattern, text)
            if match:
                return True, f"Pattern match: {pattern[:30]}..."
        
        # Check for seed phrase
        bip39_words = cls._load_bip39_words()
        words = text.split()
        if len(words) >= 12:
            cleaned = [w.strip('.,;:!?"\'-()[]{}').lower() for w in words[:24]]
            bip39_count = sum(1 for w in cleaned if w in bip39_words)
            if bip39_count >= 10:
                return True, f"Potential seed phrase ({bip39_count} BIP-39 words)"
        
        return False, ""
    
    @classmethod
    def scan_file(cls, filepath: str) -> List[Tuple[int, str, str]]:
        """Scan a file for potential secrets. Returns list of (line_number, match, reason)."""
        findings = []
        try:
            with open(filepath, 'r', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    has_secret, reason = cls.contains_secret(line)
                    if has_secret:
                        findings.append((i, line.strip()[:80], reason))
        except Exception as e:
            findings.append((0, f"Error reading file: {e}", "error"))
        return findings


# Test suite
if __name__ == "__main__":
    test_cases = [
        # Private keys
        ("My key is 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", True),
        # Raw hex key (no 0x)
        ("Key: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", True),
        # Split key (32 chars)
        ("First half: 1234567890abcdef1234567890abcdef", True),
        # Addresses (should truncate, not fully redact)
        ("Send to 0x742d35Cc6634C0532925a3b844Bc454e4438f44e", True),
        # OpenAI
        ("Using sk-proj-abc123def456ghi789jkl012mno345pqr678", True),
        # Anthropic
        ("API key is sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD", True),
        # AWS with context (should match)
        ("aws_secret_key=AKIAIOSFODNN7EXAMPLE1234567890abcdefgh", True),
        # Random base64 without context (should NOT match - was false positive)
        ("The hash is dGhpcyBpcyBhIHRlc3Qgc3RyaW5nIGZvciBiYXNl", False),
        # Seed phrase (12 words)
        ("abandon ability able about above absent absorb abstract absurd abuse access accident", True),
        # JWT
        ("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", True),
        # Normal text
        ("Normal text without secrets", False),
        # Telegram token
        ("Bot token: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz12345678", True),
    ]
    
    print("Output Sanitizer Test (v2)\n" + "=" * 60)
    passed = 0
    failed = 0
    
    for test, should_detect in test_cases:
        has_secret, reason = OutputSanitizer.contains_secret(test)
        sanitized = OutputSanitizer.sanitize(test)
        
        if has_secret == should_detect:
            status = "✅ PASS"
            passed += 1
        else:
            status = "❌ FAIL"
            failed += 1
        
        print(f"\n{status} (expect {'detect' if should_detect else 'ignore'})")
        print(f"   Input:     {test[:60]}{'...' if len(test) > 60 else ''}")
        print(f"   Sanitized: {sanitized[:60]}{'...' if len(sanitized) > 60 else ''}")
        if has_secret:
            print(f"   Reason:    {reason}")
    
    print(f"\n{'=' * 60}")
    print(f"Results: {passed} passed, {failed} failed")
