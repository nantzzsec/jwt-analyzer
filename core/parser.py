"""
core/parser.py
JWT Token Parser and Input Handler

Handles reading JWT tokens from various input sources and cleaning them
before analysis. Supports --token, --file, and --header-file inputs.
"""

import re
import os
import base64
import json
from typing import Optional, Tuple, Dict


class JWTParseError(Exception):
    """Raised when JWT cannot be parsed."""
    pass


def clean_token(raw: str) -> str:
    """
    Remove common prefixes and whitespace from a raw token string.

    Handles:
    - 'Bearer <token>' prefix
    - 'Authorization: Bearer <token>' header format
    - Surrounding whitespace/newlines
    """
    raw = raw.strip()

    # Remove full Authorization header line
    auth_header_match = re.match(
        r'^[Aa]uthorization\s*:\s*[Bb]earer\s+(.+)$',
        raw,
        re.IGNORECASE
    )
    if auth_header_match:
        return auth_header_match.group(1).strip()

    # Remove just 'Bearer ' prefix
    bearer_match = re.match(r'^[Bb]earer\s+(.+)$', raw, re.IGNORECASE)
    if bearer_match:
        return bearer_match.group(1).strip()

    return raw


def read_token_from_file(filepath: str) -> str:
    """Read and clean JWT token from a plain text file."""
    if not os.path.isfile(filepath):
        raise JWTParseError(f"File not found: {filepath}")

    with open(filepath, 'r', encoding='utf-8') as f:
        raw = f.read()

    return clean_token(raw)


def detect_token_type(token: str) -> str:
    """
    Detect whether the token is JWS (3 parts) or JWE (5 parts).

    Returns:
        'JWS' | 'JWE' | 'UNKNOWN'
    """
    parts = token.split('.')
    if len(parts) == 3:
        return 'JWS'
    elif len(parts) == 5:
        return 'JWE'
    else:
        return 'UNKNOWN'


def _pad_base64(s: str) -> str:
    """Add missing base64 padding."""
    return s + '=' * (4 - len(s) % 4) if len(s) % 4 else s


def safe_b64decode(s: str) -> bytes:
    """Safely decode base64url string."""
    s = s.replace('-', '+').replace('_', '/')
    s = _pad_base64(s)
    return base64.b64decode(s)


def decode_part(part: str) -> Dict:
    """
    Decode a base64url-encoded JWT part into a Python dict.

    Raises:
        JWTParseError if decoding or JSON parsing fails.
    """
    try:
        raw_bytes = safe_b64decode(part)
        return json.loads(raw_bytes.decode('utf-8'))
    except Exception as e:
        raise JWTParseError(f"Failed to decode JWT part: {e}")


def parse_jws(token: str) -> Tuple[Dict, Dict, str]:
    """
    Parse a JWS token into (header, payload, signature).

    Returns:
        Tuple of (header_dict, payload_dict, signature_b64url_str)
    Raises:
        JWTParseError on failure.
    """
    parts = token.split('.')
    if len(parts) != 3:
        raise JWTParseError(
            f"Expected 3 parts for JWS, got {len(parts)}."
        )

    header_b64, payload_b64, signature_b64 = parts

    try:
        header = decode_part(header_b64)
    except JWTParseError:
        raise JWTParseError("Cannot decode JWT header. Token may be malformed.")

    try:
        payload = decode_part(payload_b64)
    except JWTParseError:
        raise JWTParseError("Cannot decode JWT payload. Token may be malformed.")

    return header, payload, signature_b64


def extract_tokens_from_header_file(filepath: str) -> Dict[str, list]:
    """
    Parse an HTTP request header file and extract JWT tokens.

    Looks for:
    - Authorization: Bearer <token>
    - Cookie: <name>=<jwt_value>
    - Possible JWT in URL (query params)

    Returns a dict with keys: 'authorization', 'cookies', 'url_params'
    """
    if not os.path.isfile(filepath):
        raise JWTParseError(f"Header file not found: {filepath}")

    results = {
        'authorization': [],
        'cookies': [],
        'url_params': [],
        'raw_headers': {}
    }

    jwt_pattern = re.compile(
        r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
    )

    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Authorization header
        if re.match(r'^[Aa]uthorization\s*:', line):
            token_match = jwt_pattern.search(line)
            if token_match:
                results['authorization'].append({
                    'token': token_match.group(0),
                    'raw_line': line
                })

        # Cookie header
        elif re.match(r'^[Cc]ookie\s*:', line):
            cookie_part = re.sub(r'^[Cc]ookie\s*:\s*', '', line)
            cookies = cookie_part.split(';')
            for cookie in cookies:
                cookie = cookie.strip()
                if '=' in cookie:
                    name, value = cookie.split('=', 1)
                    token_match = jwt_pattern.match(value.strip())
                    if token_match:
                        results['cookies'].append({
                            'name': name.strip(),
                            'token': token_match.group(0),
                            'raw': cookie
                        })

        # URL line (GET /path?token=... HTTP/1.1)
        elif re.match(r'^(GET|POST|PUT|DELETE|PATCH)\s', line, re.IGNORECASE):
            url_tokens = jwt_pattern.findall(line)
            for t in url_tokens:
                results['url_params'].append({
                    'token': t,
                    'raw_line': line,
                    'warning': 'JWT found in URL — risk of token leakage via logs/referer'
                })

        # Store raw headers
        if ':' in line:
            key, _, value = line.partition(':')
            results['raw_headers'][key.strip()] = value.strip()

    return results
