"""
core/signature_verifier.py
JWT Signature Verification Module

Performs optional cryptographic signature verification using:
- HMAC (HS256/HS384/HS512) with --secret
- RSA/EC (RS256/RS384/RS512/ES256/ES512) with --public-key

Verification statuses:
- Valid: Signature cryptographically verified
- Invalid: Signature verification failed
- Not Verified: Verification was attempted but could not complete
- Key Not Provided: No key was supplied
"""

import hmac
import hashlib
import base64
from typing import Dict, Tuple, Optional
from core.header_analyzer import Finding


HMAC_HASH_MAP = {
    'HS256': hashlib.sha256,
    'HS384': hashlib.sha384,
    'HS512': hashlib.sha512,
}


def _pad_base64(s: str) -> str:
    """Add missing base64 padding."""
    return s + '=' * (4 - len(s) % 4) if len(s) % 4 else s


def _b64url_encode(data: bytes) -> str:
    """Base64url encode bytes without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def verify_signature(
    token: str,
    header: Dict,
    secret: Optional[str] = None,
    public_key_path: Optional[str] = None
) -> Tuple[str, Finding]:
    """
    Attempt to verify the JWT signature.

    Args:
        token: The full JWT string (header.payload.signature)
        header: Decoded JWT header
        secret: Shared secret for HMAC algorithms
        public_key_path: Path to PEM public key for RSA/EC algorithms

    Returns:
        Tuple of (status_string, Finding)
        status: 'Valid' | 'Invalid' | 'Not Verified' | 'Key Not Provided'
    """
    alg = header.get('alg', '')
    parts = token.split('.')

    if len(parts) != 3:
        return _not_verified("Token structure invalid for signature verification.")

    signing_input = f"{parts[0]}.{parts[1]}".encode('utf-8')
    signature_b64 = parts[2]

    # ── HMAC ────────────────────────────────────────────────────────────────
    if alg in HMAC_HASH_MAP:
        if not secret:
            return _key_not_provided(alg)
        return _verify_hmac(alg, signing_input, signature_b64, secret)

    # ── RSA / EC / PSS ───────────────────────────────────────────────────────
    rsa_algs = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']
    ec_algs = ['ES256', 'ES384', 'ES512']

    if alg in rsa_algs or alg in ec_algs:
        if not public_key_path:
            return _key_not_provided(alg)
        return _verify_asymmetric(alg, signing_input, signature_b64, public_key_path)

    # ── Algorithm none ───────────────────────────────────────────────────────
    if alg.lower() == 'none':
        finding = Finding(
            title="Signature Verification: Algorithm 'none' — No Signature to Verify",
            severity="Critical",
            confidence="Confirmed",
            evidence="Token uses alg=none. No signature is present or verifiable.",
            impact="Token carries zero cryptographic integrity guarantee.",
            recommendation="Reject all tokens with alg=none immediately.",
            category="Signature"
        )
        return "Not Verified", finding

    # ── Unknown algorithm ────────────────────────────────────────────────────
    return _not_verified(f"Algorithm '{alg}' is not supported for verification.")


def _verify_hmac(
    alg: str,
    signing_input: bytes,
    signature_b64: str,
    secret: str
) -> Tuple[str, Finding]:
    """Verify HMAC-based JWT signature."""
    hash_func = HMAC_HASH_MAP[alg]
    key = secret.encode('utf-8')

    expected_signature = hmac.new(key, signing_input, hash_func).digest()
    expected_b64 = _b64url_encode(expected_signature)

    # Decode received signature
    try:
        received_b64_padded = _pad_base64(
            signature_b64.replace('-', '+').replace('_', '/')
        )
        received_signature = base64.b64decode(received_b64_padded)
    except Exception as e:
        return _not_verified(f"Could not decode received signature: {e}")

    # Constant-time comparison to prevent timing attacks
    if hmac.compare_digest(expected_signature, received_signature):
        finding = Finding(
            title=f"Signature Verification: VALID ({alg})",
            severity="Info",
            confidence="Confirmed",
            evidence=(
                f"Algorithm: {alg} | "
                f"HMAC signature verified successfully using the provided secret."
            ),
            impact="Token signature is cryptographically valid with the provided key.",
            recommendation="Ensure the signing secret is rotated regularly and stored securely.",
            category="Signature"
        )
        return "Valid", finding
    else:
        finding = Finding(
            title=f"Signature Verification: INVALID ({alg})",
            severity="Critical",
            confidence="Confirmed",
            evidence=(
                f"Algorithm: {alg} | "
                f"Expected signature: {expected_b64[:20]}... | "
                f"Received signature: {signature_b64[:20]}..."
            ),
            impact=(
                "The token signature does not match the expected value for the "
                "provided secret. This token may have been tampered with, or "
                "the wrong secret was provided."
            ),
            recommendation=(
                "Do not accept this token. "
                "Investigate whether token tampering has occurred. "
                "Ensure the correct signing secret is used."
            ),
            category="Signature"
        )
        return "Invalid", finding


def _verify_asymmetric(
    alg: str,
    signing_input: bytes,
    signature_b64: str,
    public_key_path: str
) -> Tuple[str, Finding]:
    """Verify RSA/EC-based JWT signature using cryptography library."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, ec
        from cryptography.exceptions import InvalidSignature
        import os
    except ImportError:
        finding = Finding(
            title="Signature Verification: Library Not Available",
            severity="Info",
            confidence="Informational",
            evidence="The 'cryptography' package is not installed.",
            impact="Cannot verify asymmetric signatures without the cryptography library.",
            recommendation="Install with: pip install cryptography",
            category="Signature"
        )
        return "Not Verified", finding

    if not os.path.isfile(public_key_path):
        finding = Finding(
            title="Signature Verification: Public Key File Not Found",
            severity="Info",
            confidence="Informational",
            evidence=f"File not found: {public_key_path}",
            impact="Cannot verify signature without the public key.",
            recommendation="Provide a valid path to the PEM-encoded public key.",
            category="Signature"
        )
        return "Not Verified", finding

    try:
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
    except Exception as e:
        return _not_verified(f"Failed to load public key: {e}")

    try:
        sig_padded = _pad_base64(
            signature_b64.replace('-', '+').replace('_', '/')
        )
        signature_bytes = base64.b64decode(sig_padded)
    except Exception as e:
        return _not_verified(f"Could not decode signature: {e}")

    # Map algorithm to hash
    hash_map = {
        'RS256': hashes.SHA256(), 'RS384': hashes.SHA384(), 'RS512': hashes.SHA512(),
        'PS256': hashes.SHA256(), 'PS384': hashes.SHA384(), 'PS512': hashes.SHA512(),
        'ES256': hashes.SHA256(), 'ES384': hashes.SHA384(), 'ES512': hashes.SHA512(),
    }
    hash_alg = hash_map.get(alg)
    if not hash_alg:
        return _not_verified(f"Unsupported algorithm: {alg}")

    try:
        if alg.startswith('RS'):
            public_key.verify(signature_bytes, signing_input, padding.PKCS1v15(), hash_alg)
        elif alg.startswith('PS'):
            public_key.verify(
                signature_bytes, signing_input,
                padding.PSS(
                    mgf=padding.MGF1(hash_alg),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_alg
            )
        elif alg.startswith('ES'):
            public_key.verify(signature_bytes, signing_input, ec.ECDSA(hash_alg))

        finding = Finding(
            title=f"Signature Verification: VALID ({alg})",
            severity="Info",
            confidence="Confirmed",
            evidence=f"Algorithm: {alg} | Signature verified using provided public key.",
            impact="Token signature is cryptographically valid.",
            recommendation="Ensure the public key corresponds to the expected issuer.",
            category="Signature"
        )
        return "Valid", finding

    except InvalidSignature:
        finding = Finding(
            title=f"Signature Verification: INVALID ({alg})",
            severity="Critical",
            confidence="Confirmed",
            evidence=f"Algorithm: {alg} | Signature does not match with the provided public key.",
            impact="Token may have been tampered with or signed with a different private key.",
            recommendation="Do not accept this token. Investigate potential token forgery.",
            category="Signature"
        )
        return "Invalid", finding
    except Exception as e:
        return _not_verified(f"Verification error: {e}")


def _key_not_provided(alg: str) -> Tuple[str, Finding]:
    finding = Finding(
        title=f"Signature Verification: Key Not Provided ({alg})",
        severity="Info",
        confidence="Informational",
        evidence=f"Algorithm '{alg}' requires a key but none was supplied.",
        impact="Cannot confirm signature validity without the appropriate key.",
        recommendation=(
            "Provide --secret for HMAC algorithms or --public-key for RSA/EC algorithms."
        ),
        category="Signature"
    )
    return "Key Not Provided", finding


def _not_verified(reason: str) -> Tuple[str, Finding]:
    finding = Finding(
        title="Signature Verification: Not Verified",
        severity="Info",
        confidence="Informational",
        evidence=reason,
        impact="Signature validity could not be confirmed.",
        recommendation="Provide appropriate key material to enable signature verification.",
        category="Signature"
    )
    return "Not Verified", finding
