"""
core/cookie_analyzer.py
HTTP Header and Cookie Security Analyzer

Analyzes HTTP request/response headers for JWT-related security issues:
- Cookie attributes: HttpOnly, Secure, SameSite
- JWT in URL parameters (token leakage risk)
- Authorization header presence and format
- Security headers presence
"""

from typing import Dict, List
from core.header_analyzer import Finding


def analyze_headers_and_cookies(header_data: Dict) -> List[Finding]:
    """
    Analyze extracted HTTP header data for JWT-related security issues.

    Args:
        header_data: Dict from parser.extract_tokens_from_header_file()
            Keys: 'authorization', 'cookies', 'url_params', 'raw_headers'

    Returns:
        List of Finding objects
    """
    findings = []
    raw_headers = header_data.get('raw_headers', {})

    # ── 1. JWT in Authorization Header ───────────────────────────────────────
    auth_tokens = header_data.get('authorization', [])
    if auth_tokens:
        for item in auth_tokens:
            findings.append(Finding(
                title="JWT Found in Authorization Header",
                severity="Info",
                confidence="Confirmed",
                evidence=f"Authorization header: '{item['raw_line'][:80]}...'",
                impact="JWT is transmitted via Authorization header (standard practice).",
                recommendation=(
                    "Ensure transport uses HTTPS to prevent token interception. "
                    "Verify the token is not unnecessarily long-lived."
                ),
                category="Headers"
            ))
    else:
        findings.append(Finding(
            title="No JWT Found in Authorization Header",
            severity="Info",
            confidence="Informational",
            evidence="No 'Authorization: Bearer <jwt>' header detected in the file.",
            impact="JWT may be transmitted via another mechanism (cookie, body, URL).",
            recommendation="Prefer Authorization header over cookies or URL params for API tokens.",
            category="Headers"
        ))

    # ── 2. JWT in Cookie Header ───────────────────────────────────────────────
    cookie_tokens = header_data.get('cookies', [])
    for cookie in cookie_tokens:
        cookie_name = cookie.get('name', 'unknown')
        findings.append(Finding(
            title=f"JWT Found in Cookie: '{cookie_name}'",
            severity="Medium",
            confidence="Confirmed",
            evidence=(
                f"Cookie name: '{cookie_name}' | "
                f"Cookie contains a JWT token."
            ),
            impact=(
                "JWTs in cookies are vulnerable to CSRF attacks if not properly protected. "
                "Cookie storage also exposes tokens to XSS if HttpOnly is not set."
            ),
            recommendation=(
                "If using cookies for JWT storage: "
                "Set HttpOnly=true to prevent JavaScript access. "
                "Set Secure=true to prevent transmission over HTTP. "
                "Set SameSite=Strict or Lax to mitigate CSRF. "
                "Consider using Authorization header for API clients instead."
            ),
            category="Cookies"
        ))

    # ── 3. Cookie attribute analysis ─────────────────────────────────────────
    cookie_header_raw = ''
    for key, value in raw_headers.items():
        if key.strip().lower() in ('cookie', 'set-cookie'):
            cookie_header_raw = value

    # Check Set-Cookie header for security attributes
    set_cookie_headers = _get_all_headers(raw_headers, 'set-cookie')
    for set_cookie_val in set_cookie_headers:
        _analyze_set_cookie(set_cookie_val, findings)

    # ── 4. JWT in URL Parameters ──────────────────────────────────────────────
    url_params = header_data.get('url_params', [])
    for item in url_params:
        findings.append(Finding(
            title="JWT Found in URL Parameter — Token Leakage Risk",
            severity="High",
            confidence="Confirmed",
            evidence=(
                f"JWT detected in URL: '{item['raw_line'][:100]}'"
            ),
            impact=(
                "JWTs in URL parameters are logged by web servers, proxies, "
                "browsers, and analytics platforms. "
                "They also appear in browser history and Referer headers, "
                "making token interception trivial."
            ),
            recommendation=(
                "Never pass JWT tokens as URL query parameters. "
                "Use Authorization header or a secure HttpOnly cookie instead. "
                "If a URL-based token is unavoidable, use very short expiry times."
            ),
            category="Headers"
        ))

    # ── 5. Security Headers Check ─────────────────────────────────────────────
    _check_security_headers(raw_headers, findings)

    return findings


def _analyze_set_cookie(set_cookie_value: str, findings: List[Finding]):
    """Analyze a Set-Cookie header value for security attributes."""
    name_value = set_cookie_value.split(';')[0].strip()
    name = name_value.split('=')[0].strip() if '=' in name_value else name_value
    attrs_lower = set_cookie_value.lower()

    # Check for HttpOnly
    if 'httponly' not in attrs_lower:
        findings.append(Finding(
            title=f"Cookie '{name}': Missing HttpOnly Flag",
            severity="Medium",
            confidence="Confirmed",
            evidence=f"Set-Cookie: {set_cookie_value[:100]}",
            impact=(
                "Without HttpOnly, JavaScript can access the cookie via document.cookie. "
                "If this cookie contains a JWT or session token, XSS attacks "
                "can steal it directly."
            ),
            recommendation=(
                "Add the HttpOnly flag to all sensitive cookies: "
                "Set-Cookie: token=...; HttpOnly; Secure; SameSite=Strict"
            ),
            category="Cookies"
        ))

    # Check for Secure flag
    if 'secure' not in attrs_lower:
        findings.append(Finding(
            title=f"Cookie '{name}': Missing Secure Flag",
            severity="High",
            confidence="Confirmed",
            evidence=f"Set-Cookie: {set_cookie_value[:100]}",
            impact=(
                "Without the Secure flag, the browser may send this cookie over "
                "unencrypted HTTP connections, exposing the token to network interception."
            ),
            recommendation=(
                "Add the Secure flag to ensure cookies are only sent over HTTPS: "
                "Set-Cookie: token=...; Secure"
            ),
            category="Cookies"
        ))

    # Check for SameSite
    if 'samesite' not in attrs_lower:
        findings.append(Finding(
            title=f"Cookie '{name}': Missing SameSite Attribute",
            severity="Medium",
            confidence="Confirmed",
            evidence=f"Set-Cookie: {set_cookie_value[:100]}",
            impact=(
                "Without SameSite, the cookie is sent with all cross-site requests, "
                "making it vulnerable to Cross-Site Request Forgery (CSRF) attacks."
            ),
            recommendation=(
                "Add SameSite=Strict or SameSite=Lax: "
                "Set-Cookie: token=...; SameSite=Strict"
            ),
            category="Cookies"
        ))
    elif 'samesite=none' in attrs_lower and 'secure' not in attrs_lower:
        findings.append(Finding(
            title=f"Cookie '{name}': SameSite=None Without Secure",
            severity="High",
            confidence="Confirmed",
            evidence=f"Set-Cookie: {set_cookie_value[:100]}",
            impact=(
                "SameSite=None is used to allow cross-site access, but without Secure, "
                "modern browsers will reject the cookie or send it insecurely."
            ),
            recommendation="Pair SameSite=None with Secure flag.",
            category="Cookies"
        ))


def _get_all_headers(raw_headers: Dict, header_name: str) -> List[str]:
    """Get all header values matching a given name (case-insensitive)."""
    results = []
    for key, value in raw_headers.items():
        if key.strip().lower() == header_name.lower():
            # Value might contain multiple Set-Cookie entries
            for line in value.split('\n'):
                line = line.strip()
                if line:
                    results.append(line)
    return results


def _check_security_headers(raw_headers: Dict, findings: List[Finding]):
    """Check for important HTTP security headers."""
    headers_lower = {k.lower().strip(): v for k, v in raw_headers.items()}

    recommended_headers = {
        'strict-transport-security': (
            'HSTS (Strict-Transport-Security)',
            'Missing HSTS prevents enforcing HTTPS, enabling downgrade attacks.',
            'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
        ),
        'x-content-type-options': (
            'X-Content-Type-Options',
            'Without this header, browsers may MIME-sniff responses, enabling attacks.',
            'Add: X-Content-Type-Options: nosniff'
        ),
        'x-frame-options': (
            'X-Frame-Options',
            'Without this, the page can be embedded in iframes, enabling clickjacking.',
            'Add: X-Frame-Options: DENY or SAMEORIGIN'
        ),
    }

    for header_key, (display_name, impact, recommendation) in recommended_headers.items():
        if header_key not in headers_lower:
            findings.append(Finding(
                title=f"Security Header Missing: {display_name}",
                severity="Low",
                confidence="Informational",
                evidence=f"Header '{header_key}' not found in the provided header file.",
                impact=impact,
                recommendation=recommendation,
                category="Headers"
            ))
