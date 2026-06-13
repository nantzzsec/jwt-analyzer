"""
core/endpoint_validator.py
Safe Endpoint Validation Module

Performs authorized, non-destructive endpoint testing:
- Sends the original token to the endpoint (GET/HEAD only by default)
- Optionally sends a tampered token to detect missing signature validation
- Creates a Critical finding if tampered token is accepted

SECURITY RULES:
- Only GET/HEAD requests are sent by default
- No fuzzing, brute force, or mass scanning
- All testing assumed to be on systems the user is authorized to test
- Tamper check only modifies the signature portion (last part)
"""

import time
import re
import base64
from typing import Dict, List, Optional, Tuple
from core.header_analyzer import Finding


def _corrupt_signature(token: str) -> str:
    """
    Create a version of the token with a corrupted signature.
    Only modifies the last part (signature) to preserve header/payload.
    """
    parts = token.split('.')
    if len(parts) != 3:
        return token

    # Corrupt signature by appending 'XXXXXX' or reversing last few chars
    original_sig = parts[2]
    if len(original_sig) > 10:
        corrupted = original_sig[:-6] + 'XXXXXX'
    else:
        corrupted = 'XXXXXX' + original_sig

    return f"{parts[0]}.{parts[1]}.{corrupted}"


def _make_request(
    url: str,
    method: str,
    token: str,
    timeout: int = 10
) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """
    Make an HTTP request with Bearer token authorization.

    Returns:
        Tuple of (status_code, response_body_snippet, error_message)
    """
    try:
        import urllib.request
        import urllib.error

        req = urllib.request.Request(url, method=method)
        req.add_header('Authorization', f'Bearer {token}')
        req.add_header('User-Agent', 'jwt-security-analyzer-cli/1.0 (authorized-testing)')
        req.add_header('Accept', 'application/json, text/plain, */*')

        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(512).decode('utf-8', errors='replace')
            return response.status, body, None

    except Exception as e:
        # Try to extract status code from HTTP errors
        if hasattr(e, 'code'):
            return e.code, None, str(e)
        return None, None, str(e)


def validate_endpoint(
    token: str,
    endpoint: str,
    method: str = 'GET',
    timeout: int = 10,
    perform_tamper_check: bool = False
) -> List[Finding]:
    """
    Perform safe endpoint validation with the JWT token.

    Args:
        token: The original JWT token string
        endpoint: Target URL to validate against
        method: HTTP method (GET or HEAD)
        timeout: Request timeout in seconds
        perform_tamper_check: If True, also sends a tampered token

    Returns:
        List of Finding objects
    """
    findings = []
    allowed_methods = ('GET', 'HEAD')

    # ── Safety check: only allow GET/HEAD ───────────────────────────────────
    method = method.upper()
    if method not in allowed_methods:
        findings.append(Finding(
            title=f"Endpoint Validation: Method '{method}' Not Allowed",
            severity="Info",
            confidence="Informational",
            evidence=f"Requested method: {method} | Allowed: {allowed_methods}",
            impact="Only GET and HEAD methods are permitted for safe validation.",
            recommendation="Use GET or HEAD for endpoint validation.",
            category="Endpoint"
        ))
        return findings

    # ── URL validation ───────────────────────────────────────────────────────
    if not re.match(r'^https?://', endpoint, re.IGNORECASE):
        findings.append(Finding(
            title="Endpoint Validation: Invalid URL Format",
            severity="Info",
            confidence="Informational",
            evidence=f"Endpoint: '{endpoint}' — must start with http:// or https://",
            impact="Cannot validate endpoint with malformed URL.",
            recommendation="Provide a valid HTTP/HTTPS URL for endpoint validation.",
            category="Endpoint"
        ))
        return findings

    # ── Primary token request ─────────────────────────────────────────────────
    print(f"[*] Sending {method} request to: {endpoint}")
    status_original, body_original, err_original = _make_request(
        endpoint, method, token, timeout
    )

    if err_original and status_original is None:
        findings.append(Finding(
            title="Endpoint Validation: Connection Failed",
            severity="Info",
            confidence="Informational",
            evidence=f"Endpoint: {endpoint} | Error: {err_original}",
            impact="Could not reach the endpoint for validation.",
            recommendation="Ensure the endpoint is reachable and the URL is correct.",
            category="Endpoint"
        ))
        return findings

    # Interpret original token response
    _add_response_finding(findings, endpoint, method, token, status_original, "Original Token")

    # ── Tamper check ─────────────────────────────────────────────────────────
    if perform_tamper_check:
        corrupted_token = _corrupt_signature(token)
        print(f"[*] Sending tamper-check request with corrupted signature...")
        time.sleep(0.5)  # Small delay between requests

        status_tampered, body_tampered, err_tampered = _make_request(
            endpoint, method, corrupted_token, timeout
        )

        if err_tampered and status_tampered is None:
            findings.append(Finding(
                title="Tamper Check: Connection Failed for Corrupted Token Request",
                severity="Info",
                confidence="Informational",
                evidence=f"Error during tamper check: {err_tampered}",
                impact="Could not complete tamper check.",
                recommendation="Retry when the endpoint is available.",
                category="Endpoint"
            ))
        else:
            _add_tamper_finding(
                findings, endpoint,
                status_original, status_tampered,
                body_original, body_tampered
            )

    return findings


def _add_response_finding(
    findings: List[Finding],
    endpoint: str,
    method: str,
    token: str,
    status: Optional[int],
    label: str
):
    """Add a finding based on the HTTP response status code."""
    if status in (200, 201, 204):
        severity = "Info"
        confidence = "Confirmed"
        title = f"Endpoint Validation: Token Accepted (HTTP {status})"
        impact = "Server accepted the token and returned a success response."
        recommendation = "Confirm this is expected behavior for an authorized token."
    elif status in (401, 403):
        severity = "Info"
        confidence = "Confirmed"
        title = f"Endpoint Validation: Token Rejected (HTTP {status})"
        impact = "Server correctly rejected the token with an auth error."
        recommendation = "Review whether rejection is expected (expired token, wrong audience, etc.)"
    elif status in (404,):
        severity = "Low"
        confidence = "Informational"
        title = f"Endpoint Validation: Resource Not Found (HTTP {status})"
        impact = "Endpoint returned 404. Token may be valid but resource does not exist."
        recommendation = "Verify the endpoint URL is correct."
    elif status is not None and status >= 500:
        severity = "Medium"
        confidence = "Potential"
        title = f"Endpoint Validation: Server Error (HTTP {status})"
        impact = "Server returned an error. May indicate misconfiguration or a backend issue."
        recommendation = "Investigate server-side logs for the cause of the error."
    else:
        severity = "Info"
        confidence = "Informational"
        title = f"Endpoint Validation: HTTP {status}"
        impact = f"Unexpected HTTP status code: {status}"
        recommendation = "Manually review the response for this status code."

    findings.append(Finding(
        title=title,
        severity=severity,
        confidence=confidence,
        evidence=(
            f"Endpoint: {endpoint} | "
            f"Method: {method} | "
            f"Token: {label} | "
            f"HTTP Status: {status}"
        ),
        impact=impact,
        recommendation=recommendation,
        category="Endpoint"
    ))


def _add_tamper_finding(
    findings: List[Finding],
    endpoint: str,
    status_original: Optional[int],
    status_tampered: Optional[int],
    body_original: Optional[str],
    body_tampered: Optional[str]
):
    """
    Compare original vs tampered token responses and create appropriate findings.
    """
    original_accepted = status_original in (200, 201, 204)
    tampered_accepted = status_tampered in (200, 201, 204)

    if original_accepted and tampered_accepted:
        # CRITICAL: Server accepted both valid and invalid signatures
        findings.append(Finding(
            title="[CRITICAL] Signature Not Validated — Tampered Token Accepted",
            severity="Critical",
            confidence="Confirmed",
            evidence=(
                f"Endpoint: {endpoint} | "
                f"Original token HTTP: {status_original} (accepted) | "
                f"Corrupted signature HTTP: {status_tampered} (also accepted) | "
                "Server accepted a token with a deliberately corrupted signature."
            ),
            impact=(
                "The server appears to accept JWT tokens without validating their "
                "cryptographic signature. An attacker could forge arbitrary claims "
                "without knowing the signing secret, enabling complete authentication "
                "bypass and privilege escalation."
            ),
            recommendation=(
                "IMMEDIATE ACTION REQUIRED: "
                "Configure your JWT library to enforce signature validation. "
                "Never accept unsigned or improperly signed tokens. "
                "Whitelist allowed algorithms and reject alg=none. "
                "This is a critical authentication vulnerability."
            ),
            category="Endpoint"
        ))
    elif original_accepted and not tampered_accepted:
        findings.append(Finding(
            title="Tamper Check: Signature Validation Working Correctly",
            severity="Info",
            confidence="Confirmed",
            evidence=(
                f"Endpoint: {endpoint} | "
                f"Original token HTTP: {status_original} (accepted) | "
                f"Corrupted signature HTTP: {status_tampered} (rejected) | "
                "Server correctly rejected the tampered token."
            ),
            impact="Server properly validates JWT signatures.",
            recommendation=(
                "Continue monitoring for any configuration changes that could "
                "disable signature validation."
            ),
            category="Endpoint"
        ))
    elif not original_accepted:
        findings.append(Finding(
            title="Tamper Check: Original Token Was Not Accepted",
            severity="Info",
            confidence="Informational",
            evidence=(
                f"Original token HTTP: {status_original} | "
                f"Tampered token HTTP: {status_tampered} | "
                "Cannot determine if signature validation is enforced because "
                "the original token was also rejected."
            ),
            impact=(
                "Inconclusive tamper check result. "
                "Original token rejection may be due to expiration, wrong audience, "
                "or server-side issues unrelated to signature validation."
            ),
            recommendation=(
                "Use a valid, non-expired token for tamper check testing. "
                "Ensure the token has correct issuer and audience for this endpoint."
            ),
            category="Endpoint"
        ))
