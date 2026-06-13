"""
core/claim_analyzer.py
JWT Claims / Payload Security Analyzer

Analyzes JWT payload claims for security issues including:
- Expiration (exp), issued-at (iat), not-before (nbf) validation
- Required claims enforcement
- Issuer/audience validation
- Token lifetime checks
- Missing security-critical claims
"""

import time
from typing import Dict, List, Optional
from core.header_analyzer import Finding


def analyze_claims(
    payload: Dict,
    policy: Dict = None
) -> List[Finding]:
    """
    Analyze JWT payload claims for security issues.

    Args:
        payload: Decoded JWT payload dict
        policy: Optional policy configuration dict

    Returns:
        List of Finding objects
    """
    findings = []
    policy = policy or {}
    now = time.time()

    expected_issuer = policy.get('expected_issuer')
    expected_audience = policy.get('expected_audience')
    required_claims = policy.get('required_claims', [])
    max_lifetime_minutes = policy.get('max_lifetime_minutes', 1440)  # 24h default

    # ── 1. Expiration (exp) ──────────────────────────────────────────────────
    exp = payload.get('exp')
    if exp is None:
        findings.append(Finding(
            title="Missing 'exp' (Expiration) Claim",
            severity="High",
            confidence="Confirmed",
            evidence="'exp' field is not present in the JWT payload.",
            impact=(
                "Tokens without expiration are valid indefinitely. "
                "If a token is leaked or compromised, it cannot be invalidated "
                "by simply waiting for it to expire — requiring full key rotation."
            ),
            recommendation=(
                "Always include an 'exp' claim with a short-lived validity window. "
                "Recommended: 15 minutes for access tokens, up to 24 hours maximum."
            ),
            category="Claims"
        ))
    else:
        if not isinstance(exp, (int, float)):
            findings.append(Finding(
                title="'exp' Claim Has Invalid Type",
                severity="Medium",
                confidence="Confirmed",
                evidence=f"'exp' value '{exp}' is type {type(exp).__name__}, expected integer.",
                impact="Invalid exp type may cause library-specific parsing errors or be ignored.",
                recommendation="Ensure 'exp' is a NumericDate (Unix timestamp integer).",
                category="Claims"
            ))
        elif exp < now:
            elapsed = now - exp
            elapsed_str = _format_duration(elapsed)
            findings.append(Finding(
                title="Token Is Expired",
                severity="Medium",
                confidence="Confirmed",
                evidence=(
                    f"'exp' = {int(exp)} | "
                    f"Current time = {int(now)} | "
                    f"Expired {elapsed_str} ago"
                ),
                impact=(
                    "This token is past its expiry date. "
                    "If a server accepts expired tokens without strict validation, "
                    "it may indicate a vulnerability. "
                    "For static analysis purposes, an expired token in use "
                    "suggests a rotation/invalidation issue."
                ),
                recommendation=(
                    "Ensure the server strictly validates 'exp'. "
                    "Implement token refresh flows so clients do not need to "
                    "use expired tokens."
                ),
                category="Claims"
            ))
        else:
            remaining = exp - now
            findings.append(Finding(
                title="Token Expiration: Valid",
                severity="Info",
                confidence="Confirmed",
                evidence=(
                    f"'exp' = {int(exp)} | "
                    f"Expires in {_format_duration(remaining)}"
                ),
                impact="Token has not yet expired.",
                recommendation="Monitor token lifetime to ensure it aligns with policy.",
                category="Claims"
            ))

    # ── 2. Issued At (iat) ───────────────────────────────────────────────────
    iat = payload.get('iat')
    if iat is None:
        findings.append(Finding(
            title="Missing 'iat' (Issued At) Claim",
            severity="Low",
            confidence="Confirmed",
            evidence="'iat' field is not present in the JWT payload.",
            impact="Without 'iat', token age cannot be computed, making lifetime validation impossible.",
            recommendation="Include 'iat' in all issued tokens to enable age-based validation.",
            category="Claims"
        ))
    else:
        if isinstance(iat, (int, float)) and iat > now + 60:
            skew = iat - now
            findings.append(Finding(
                title="'iat' (Issued At) Is in the Future",
                severity="Medium",
                confidence="Confirmed",
                evidence=(
                    f"'iat' = {int(iat)} | "
                    f"Current time = {int(now)} | "
                    f"Future skew: {_format_duration(skew)}"
                ),
                impact=(
                    "A future 'iat' may indicate clock skew, token manipulation, "
                    "or a replayed/pre-generated token. "
                    "Servers that trust a future 'iat' may accept manipulated tokens."
                ),
                recommendation=(
                    "Validate 'iat' on the server side. "
                    "Allow a small clock skew tolerance (e.g., 60 seconds) but "
                    "reject tokens with future 'iat' beyond that window."
                ),
                category="Claims"
            ))

    # ── 3. Not Before (nbf) ──────────────────────────────────────────────────
    nbf = payload.get('nbf')
    if nbf is not None:
        if isinstance(nbf, (int, float)) and nbf > now + 60:
            findings.append(Finding(
                title="Token Not Yet Valid ('nbf' in Future)",
                severity="Medium",
                confidence="Confirmed",
                evidence=(
                    f"'nbf' = {int(nbf)} | "
                    f"Current time = {int(now)} | "
                    f"Valid in: {_format_duration(nbf - now)}"
                ),
                impact=(
                    "This token cannot be used yet. "
                    "If a server ignores 'nbf' validation, "
                    "pre-issued tokens may be accepted prematurely."
                ),
                recommendation=(
                    "Ensure the server validates 'nbf' and rejects tokens "
                    "used before their validity period begins."
                ),
                category="Claims"
            ))

    # ── 4. Token Lifetime ────────────────────────────────────────────────────
    if isinstance(iat, (int, float)) and isinstance(exp, (int, float)):
        lifetime_seconds = exp - iat
        lifetime_minutes = lifetime_seconds / 60
        if lifetime_seconds < 0:
            findings.append(Finding(
                title="'exp' Is Before 'iat' — Invalid Token Lifetime",
                severity="High",
                confidence="Confirmed",
                evidence=f"iat={int(iat)}, exp={int(exp)}, lifetime={lifetime_seconds}s",
                impact="Negative token lifetime indicates token manipulation or server-side misconfiguration.",
                recommendation="Ensure 'exp' is always greater than 'iat' when issuing tokens.",
                category="Claims"
            ))
        elif lifetime_minutes > max_lifetime_minutes:
            findings.append(Finding(
                title=f"Excessive Token Lifetime: {_format_duration(lifetime_seconds)}",
                severity="Medium",
                confidence="Confirmed",
                evidence=(
                    f"Token lifetime: {_format_duration(lifetime_seconds)} | "
                    f"Policy maximum: {max_lifetime_minutes} minutes"
                ),
                impact=(
                    "Long-lived tokens increase the window of opportunity for "
                    "token theft and misuse. If a token is compromised, it "
                    "remains valid for an extended period."
                ),
                recommendation=(
                    f"Reduce token lifetime to at most {max_lifetime_minutes} minutes. "
                    "Use refresh tokens for long-lived sessions instead of "
                    "long-lived access tokens."
                ),
                category="Claims"
            ))

    # ── 5. Issuer (iss) ──────────────────────────────────────────────────────
    iss = payload.get('iss')
    if iss is None:
        findings.append(Finding(
            title="Missing 'iss' (Issuer) Claim",
            severity="Medium",
            confidence="Confirmed",
            evidence="'iss' field not found in payload.",
            impact=(
                "Without an issuer claim, it is impossible to verify that the token "
                "was issued by a trusted authorization server."
            ),
            recommendation=(
                "Include 'iss' in all tokens and validate it server-side "
                "against a known, trusted issuer list."
            ),
            category="Claims"
        ))
    elif expected_issuer and iss != expected_issuer:
        findings.append(Finding(
            title="Issuer Mismatch",
            severity="High",
            confidence="Confirmed",
            evidence=f"Token 'iss': '{iss}' | Expected: '{expected_issuer}'",
            impact=(
                "An unexpected issuer may indicate a token from a different environment, "
                "a forged token, or a token intended for a different service."
            ),
            recommendation=(
                "Strictly validate the 'iss' claim on the server. "
                "Reject tokens from unexpected issuers."
            ),
            category="Claims"
        ))
    else:
        findings.append(Finding(
            title=f"Issuer Identified: '{iss}'",
            severity="Info",
            confidence="Informational",
            evidence=f"'iss' = '{iss}'",
            impact="Issuer claim is present.",
            recommendation=(
                "Ensure the server validates 'iss' against a trusted list."
                if not expected_issuer
                else "Issuer matches expected value."
            ),
            category="Claims"
        ))

    # ── 6. Audience (aud) ────────────────────────────────────────────────────
    aud = payload.get('aud')
    if aud is None:
        findings.append(Finding(
            title="Missing 'aud' (Audience) Claim",
            severity="Medium",
            confidence="Confirmed",
            evidence="'aud' field not found in payload.",
            impact=(
                "Without audience validation, a token issued for service A "
                "could potentially be reused against service B."
            ),
            recommendation=(
                "Include 'aud' and validate it on the server. "
                "Each service should only accept tokens with its own audience."
            ),
            category="Claims"
        ))
    elif expected_audience:
        aud_list = [aud] if isinstance(aud, str) else aud
        if expected_audience not in aud_list:
            findings.append(Finding(
                title="Audience Mismatch",
                severity="High",
                confidence="Confirmed",
                evidence=f"Token 'aud': {aud} | Expected: '{expected_audience}'",
                impact="Token not intended for this service — potential token substitution attack.",
                recommendation="Validate 'aud' strictly. Reject tokens with mismatched audience.",
                category="Claims"
            ))

    # ── 7. Subject (sub) ─────────────────────────────────────────────────────
    sub = payload.get('sub')
    if sub is None:
        findings.append(Finding(
            title="Missing 'sub' (Subject) Claim",
            severity="Low",
            confidence="Informational",
            evidence="'sub' field not found in payload.",
            impact="Without 'sub', associating the token with a specific user may be ambiguous.",
            recommendation="Include 'sub' to clearly identify the token subject.",
            category="Claims"
        ))

    # ── 8. JTI (JWT ID) — Replay Protection ──────────────────────────────────
    jti = payload.get('jti')
    if jti is None:
        findings.append(Finding(
            title="Missing 'jti' (JWT ID) — No Replay Protection",
            severity="Low",
            confidence="Informational",
            evidence="'jti' field not found in payload.",
            impact=(
                "Without 'jti', the server cannot track individual tokens to "
                "prevent replay attacks. A stolen token can be reused unlimited times "
                "until it expires."
            ),
            recommendation=(
                "Include a unique 'jti' in each token and implement a "
                "used-token blocklist to prevent replay attacks."
            ),
            category="Claims"
        ))

    # ── 9. Required Claims Policy Enforcement ────────────────────────────────
    for claim in required_claims:
        if claim not in payload:
            findings.append(Finding(
                title=f"Required Claim Missing: '{claim}'",
                severity="Medium",
                confidence="Confirmed",
                evidence=f"Claim '{claim}' required by policy but not found in payload.",
                impact=f"Missing required claim '{claim}' may cause application logic failures or security gaps.",
                recommendation=f"Ensure '{claim}' is included in all issued tokens per security policy.",
                category="Claims"
            ))

    return findings


def _format_duration(seconds: float) -> str:
    """Format a duration in seconds to a human-readable string."""
    seconds = abs(int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        m, s = divmod(seconds, 60)
        return f"{m}m {s}s"
    elif seconds < 86400:
        h, rem = divmod(seconds, 3600)
        m = rem // 60
        return f"{h}h {m}m"
    else:
        d, rem = divmod(seconds, 86400)
        h = rem // 3600
        return f"{d}d {h}h"
