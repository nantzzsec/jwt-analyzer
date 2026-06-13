"""
core/header_analyzer.py
JWT Header Security Analyzer

Analyzes JWT header fields for security issues including:
- Algorithm weaknesses (none, missing, weak)
- Suspicious kid values
- External key references (jku, x5u)
- typ field checks
"""

from typing import Dict, List
from dataclasses import dataclass, field


DANGEROUS_ALGORITHMS = ['none', 'NONE', 'None']
SYMMETRIC_ALGORITHMS = ['HS256', 'HS384', 'HS512']
ASYMMETRIC_ALGORITHMS = [
    'RS256', 'RS384', 'RS512',
    'ES256', 'ES384', 'ES512',
    'PS256', 'PS384', 'PS512',
    'EdDSA'
]
ALL_KNOWN_ALGORITHMS = SYMMETRIC_ALGORITHMS + ASYMMETRIC_ALGORITHMS + DANGEROUS_ALGORITHMS

SUSPICIOUS_KID_PATTERNS = [
    '../', '..\\',          # Path traversal
    ';', '|', '&&', '||',   # Command injection
    "'", '"',               # SQL injection chars
    '<', '>',               # XSS
    '\n', '\r', '\x00',     # Injection via newlines/nullbytes
    'SELECT', 'UNION',      # SQL keywords
    '/etc/', 'passwd',      # Unix path patterns
]


@dataclass
class Finding:
    title: str
    severity: str       # Critical, High, Medium, Low, Info
    confidence: str     # Confirmed, Potential, Informational
    evidence: str
    impact: str
    recommendation: str
    category: str = "Header"


def analyze_header(header: Dict, policy: Dict = None) -> List[Finding]:
    """
    Analyze JWT header for security issues.

    Args:
        header: Decoded JWT header dict
        policy: Optional policy config dict

    Returns:
        List of Finding objects
    """
    findings = []
    policy = policy or {}
    allowed_algorithms = policy.get('allowed_algorithms', ALL_KNOWN_ALGORITHMS)

    # ── 1. Algorithm: none ──────────────────────────────────────────────────
    alg = header.get('alg')

    if alg is None:
        findings.append(Finding(
            title="Missing 'alg' Field in JWT Header",
            severity="High",
            confidence="Confirmed",
            evidence=f"JWT header does not contain 'alg' field. Header: {header}",
            impact=(
                "Servers that do not enforce algorithm validation may accept "
                "tokens without cryptographic verification, enabling unauthorized "
                "access if combined with algorithm confusion."
            ),
            recommendation=(
                "Always include a specific, strong algorithm in the JWT header. "
                "Validate 'alg' server-side before processing the token."
            )
        ))

    elif alg.lower() == 'none':
        findings.append(Finding(
            title="Algorithm Set to 'none' — Signature Bypass Risk",
            severity="Critical",
            confidence="Confirmed",
            evidence=f"'alg' field value: '{alg}'",
            impact=(
                "Tokens using 'alg: none' carry no cryptographic signature. "
                "If a server accepts this token type, an attacker can forge "
                "arbitrary claims without a secret key — leading to authentication "
                "bypass and privilege escalation."
            ),
            recommendation=(
                "Reject all tokens with alg=none on the server side. "
                "Whitelist only specific, strong algorithms (RS256, ES256, etc.). "
                "Never trust the algorithm from the token header alone."
            )
        ))

    else:
        # ── 2. Algorithm not in allowed list ─────────────────────────────────
        if alg not in allowed_algorithms:
            findings.append(Finding(
                title=f"Algorithm '{alg}' Not in Allowed Algorithm List",
                severity="Medium",
                confidence="Potential",
                evidence=(
                    f"Token uses alg='{alg}'. "
                    f"Policy allowed_algorithms: {allowed_algorithms}"
                ),
                impact=(
                    "Using non-whitelisted algorithms may indicate misconfiguration "
                    "or an attempt to exploit algorithm confusion vulnerabilities."
                ),
                recommendation=(
                    "Configure your JWT library to explicitly whitelist allowed "
                    "algorithms. Never derive the algorithm from the token header."
                )
            ))

        # ── 3. Algorithm not recognized at all ───────────────────────────────
        if alg not in ALL_KNOWN_ALGORITHMS:
            findings.append(Finding(
                title=f"Unrecognized JWT Algorithm: '{alg}'",
                severity="High",
                confidence="Potential",
                evidence=f"'alg' value '{alg}' is not a standard JOSE algorithm.",
                impact=(
                    "Unknown algorithms may be improperly handled by JWT libraries, "
                    "potentially disabling signature verification entirely."
                ),
                recommendation=(
                    "Use only well-established JOSE algorithms. "
                    "Verify library support and security posture for any algorithm used."
                )
            ))

    # ── 4. typ field check ───────────────────────────────────────────────────
    typ = header.get('typ')
    if typ is None:
        findings.append(Finding(
            title="Missing 'typ' Field in JWT Header",
            severity="Low",
            confidence="Informational",
            evidence="JWT header does not contain 'typ' field.",
            impact=(
                "While not required by RFC 7519, the absence of 'typ' "
                "may cause interoperability issues or confusion."
            ),
            recommendation=(
                "Include 'typ': 'JWT' in the header for clarity and "
                "interoperability with strict JWT parsers."
            )
        ))
    elif typ.upper() not in ('JWT', 'JWE', 'JWS', 'AT+JWT', 'dpop+jwt'):
        findings.append(Finding(
            title=f"Unusual 'typ' Field Value: '{typ}'",
            severity="Low",
            confidence="Informational",
            evidence=f"Token 'typ' field contains non-standard value: '{typ}'",
            impact="Non-standard typ values may indicate token misuse or custom formats.",
            recommendation="Use standard typ values ('JWT', 'AT+JWT', etc.) as defined in RFC 7519."
        ))

    # ── 5. kid — suspicious characters ───────────────────────────────────────
    kid = header.get('kid')
    if kid is not None:
        kid_str = str(kid)
        suspicious_found = [
            p for p in SUSPICIOUS_KID_PATTERNS if p in kid_str
        ]
        if suspicious_found:
            findings.append(Finding(
                title="Suspicious Characters in 'kid' (Key ID) Field",
                severity="High",
                confidence="Potential",
                evidence=(
                    f"'kid' value: '{kid_str}'. "
                    f"Suspicious patterns detected: {suspicious_found}"
                ),
                impact=(
                    "If the server uses 'kid' to look up keys from a database "
                    "or filesystem without sanitization, this may enable "
                    "SQL injection, path traversal, or command injection."
                ),
                recommendation=(
                    "Sanitize and validate the 'kid' value before using it for "
                    "key lookup. Use UUIDs or opaque identifiers for kid values."
                )
            ))
        else:
            findings.append(Finding(
                title=f"'kid' Field Present: '{kid_str}'",
                severity="Info",
                confidence="Informational",
                evidence=f"'kid' header value: '{kid_str}'",
                impact="No immediate risk detected. Key ID is used for key selection.",
                recommendation="Ensure server-side key lookup is properly sanitized."
            ))

    # ── 6. jku — external JWK Set URL ────────────────────────────────────────
    jku = header.get('jku')
    if jku is not None:
        findings.append(Finding(
            title="'jku' (JWK Set URL) Header Present — SSRF Risk",
            severity="Critical",
            confidence="Potential",
            evidence=f"'jku' header value: '{jku}'",
            impact=(
                "If the server fetches keys from the 'jku' URL without strict "
                "validation, an attacker can supply a URL pointing to their own "
                "JWK Set, forcing the server to use attacker-controlled keys for "
                "verification — enabling full token forgery."
            ),
            recommendation=(
                "Never accept 'jku' from the token header to fetch verification keys. "
                "Whitelist allowed JWK Set URLs server-side. "
                "Prefer using static, pre-configured keys."
            )
        ))

    # ── 7. x5u — external X.509 certificate URL ──────────────────────────────
    x5u = header.get('x5u')
    if x5u is not None:
        findings.append(Finding(
            title="'x5u' (X.509 Certificate URL) Header Present — SSRF/Forgery Risk",
            severity="Critical",
            confidence="Potential",
            evidence=f"'x5u' header value: '{x5u}'",
            impact=(
                "Similar to 'jku', an attacker may supply a crafted 'x5u' URL "
                "to force the server to fetch and trust an attacker-controlled "
                "certificate for signature verification."
            ),
            recommendation=(
                "Ignore 'x5u' from untrusted tokens. "
                "Use only pre-loaded, trusted certificates for JWT verification."
            )
        ))

    # ── 8. x5c — embedded certificate chain ──────────────────────────────────
    x5c = header.get('x5c')
    if x5c is not None:
        findings.append(Finding(
            title="'x5c' (X.509 Certificate Chain) Embedded in Header",
            severity="Medium",
            confidence="Potential",
            evidence="'x5c' field is present in the JWT header.",
            impact=(
                "If the server uses the embedded certificate directly for "
                "verification without validating it against a trusted CA, "
                "an attacker can embed their own certificate to forge tokens."
            ),
            recommendation=(
                "Validate the x5c certificate chain against a trusted CA. "
                "Do not trust self-signed certificates from the token header."
            )
        ))

    # ── 9. crit — critical extensions ────────────────────────────────────────
    crit = header.get('crit')
    if crit is not None:
        findings.append(Finding(
            title="'crit' (Critical Extensions) Header Present",
            severity="Medium",
            confidence="Informational",
            evidence=f"'crit' header value: {crit}",
            impact=(
                "Servers must process all 'crit' extensions. "
                "Unknown extensions in 'crit' may cause improper handling "
                "or be exploited if extensions are not validated."
            ),
            recommendation=(
                "Ensure all listed critical extensions are supported and "
                "validated by your JWT library."
            )
        ))

    return findings
