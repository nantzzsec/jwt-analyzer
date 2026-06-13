"""
core/sensitive_detector.py
Sensitive Data Detection in JWT Payload

Detects potentially sensitive data in JWT claims using:
- Keyword matching (configurable via policy)
- Regex pattern matching
- Shannon entropy analysis for high-entropy strings
- Specific patterns: password, secret, api_key, private_key,
  refresh_token, access_token, client_secret, etc.
"""

import re
import math
import json
from typing import Dict, List, Any
from core.header_analyzer import Finding


# Default sensitive keywords to search in claim keys and values
DEFAULT_SENSITIVE_KEYWORDS = [
    'password', 'passwd', 'pwd',
    'secret', 'client_secret',
    'api_key', 'apikey', 'api-key',
    'private_key', 'privatekey',
    'refresh_token', 'refreshtoken',
    'access_token', 'accesstoken',
    'token', 'auth_token',
    'credit_card', 'creditcard', 'card_number',
    'ssn', 'social_security',
    'private', 'confidential',
    'internal', 'restricted',
]

# Regex patterns for sensitive data values
SENSITIVE_VALUE_PATTERNS = [
    (r'^\$2[ayb]\$.{56}$', 'bcrypt hash'),
    (r'^[0-9a-f]{32}$', 'MD5 hash / possible token'),
    (r'^[0-9a-f]{40}$', 'SHA1 hash'),
    (r'^[0-9a-f]{64}$', 'SHA256 hash'),
    (r'-----BEGIN.*PRIVATE KEY-----', 'PEM private key'),
    (r'-----BEGIN.*CERTIFICATE-----', 'PEM certificate'),
    (r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$',
     'Base64-encoded data (≥32 chars)'),
    (r'(?i)bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
     'Nested JWT/Bearer token'),
    (r'(?i)(sk_live|sk_test|pk_live|pk_test)_[A-Za-z0-9]{20,}',
     'Stripe API key pattern'),
    (r'(?i)AKIA[0-9A-Z]{16}', 'AWS Access Key ID pattern'),
    (r'(?i)ghp_[A-Za-z0-9]{36}', 'GitHub Personal Access Token'),
]

# Minimum entropy threshold to flag a value as high-entropy
ENTROPY_THRESHOLD = 4.0
# Minimum string length for entropy analysis
ENTROPY_MIN_LENGTH = 16


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def _flatten_dict(data: Any, prefix: str = '') -> Dict[str, Any]:
    """
    Recursively flatten a nested dict/list into key-value pairs.

    Example:
        {'user': {'name': 'Alice', 'roles': ['admin']}}
        → {'user.name': 'Alice', 'user.roles[0]': 'admin'}
    """
    items = {}
    if isinstance(data, dict):
        for k, v in data.items():
            full_key = f"{prefix}.{k}" if prefix else str(k)
            items.update(_flatten_dict(v, full_key))
    elif isinstance(data, list):
        for i, v in enumerate(data):
            full_key = f"{prefix}[{i}]"
            items.update(_flatten_dict(v, full_key))
    else:
        items[prefix] = data
    return items


def detect_sensitive_data(
    payload: Dict,
    policy: Dict = None
) -> List[Finding]:
    """
    Scan JWT payload for sensitive data indicators.

    Args:
        payload: Decoded JWT payload dict
        policy: Optional policy config with 'sensitive_keywords' list

    Returns:
        List of Finding objects
    """
    findings = []
    policy = policy or {}

    # Merge default + policy keywords
    policy_keywords = policy.get('sensitive_keywords', [])
    all_keywords = list(set(DEFAULT_SENSITIVE_KEYWORDS + policy_keywords))

    # Flatten payload for analysis
    flat = _flatten_dict(payload)

    for claim_path, value in flat.items():
        value_str = str(value) if not isinstance(value, str) else value
        claim_lower = claim_path.lower()

        # ── 1. Keyword match in key name ─────────────────────────────────────
        matched_keywords = [
            kw for kw in all_keywords
            if kw.lower() in claim_lower
        ]
        if matched_keywords:
            findings.append(Finding(
                title=f"Sensitive Keyword in Claim Name: '{claim_path}'",
                severity="High",
                confidence="Potential",
                evidence=(
                    f"Claim path: '{claim_path}' | "
                    f"Value type: {type(value).__name__} | "
                    f"Matched keywords: {matched_keywords}"
                ),
                impact=(
                    "Sensitive data embedded directly in a JWT payload is accessible "
                    "to anyone who can base64-decode the token (unauthenticated). "
                    "JWT payloads are NOT encrypted by default — only base64-encoded."
                ),
                recommendation=(
                    "Never store passwords, secrets, private keys, or sensitive PII "
                    "in JWT payloads. Store only opaque identifiers and fetch "
                    "sensitive data server-side."
                ),
                category="Sensitive Data"
            ))
            continue  # Skip further checks for this field to avoid duplicate findings

        # ── 2. Regex pattern match on value ───────────────────────────────────
        if isinstance(value_str, str) and len(value_str) >= 8:
            for pattern, description in SENSITIVE_VALUE_PATTERNS:
                # Skip base64 pattern for short strings
                if 'Base64' in description and len(value_str) < 32:
                    continue
                if re.search(pattern, value_str):
                    findings.append(Finding(
                        title=f"Potential Sensitive Value in '{claim_path}': {description}",
                        severity="Medium",
                        confidence="Potential",
                        evidence=(
                            f"Claim: '{claim_path}' | "
                            f"Pattern: {description} | "
                            f"Value (truncated): '{value_str[:40]}{'...' if len(value_str) > 40 else ''}'"
                        ),
                        impact=(
                            f"Value matching '{description}' pattern found in JWT payload. "
                            "This may indicate sensitive data embedded in the token."
                        ),
                        recommendation=(
                            "Review whether this value needs to be in the JWT payload. "
                            "Consider moving sensitive values server-side and using "
                            "opaque references instead."
                        ),
                        category="Sensitive Data"
                    ))
                    break  # One finding per claim value

        # ── 3. High-entropy string detection ─────────────────────────────────
        if (
            isinstance(value_str, str)
            and len(value_str) >= ENTROPY_MIN_LENGTH
            and not any(kw.lower() in claim_lower for kw in all_keywords)
        ):
            entropy = _shannon_entropy(value_str)
            if entropy >= ENTROPY_THRESHOLD:
                findings.append(Finding(
                    title=f"High-Entropy Value in Claim '{claim_path}'",
                    severity="Low",
                    confidence="Informational",
                    evidence=(
                        f"Claim: '{claim_path}' | "
                        f"Shannon entropy: {entropy:.2f} bits | "
                        f"Length: {len(value_str)} chars | "
                        f"Value (truncated): '{value_str[:40]}{'...' if len(value_str) > 40 else ''}'"
                    ),
                    impact=(
                        "High-entropy strings may indicate encoded secrets, keys, or "
                        "encrypted data embedded in the JWT payload."
                    ),
                    recommendation=(
                        "Review this value to confirm it is not a secret or key. "
                        "Entropy analysis is a heuristic — manual review required."
                    ),
                    category="Sensitive Data"
                ))

    return findings
