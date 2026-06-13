# 🔐 JWT Security Analysis Report

**Tool**: jwt-security-analyzer-cli v1.0.0  
**Generated**: 2026-06-13 02:49:39 UTC

---

## Token Overview

| Field | Value |
|-------|-------|
| Token (truncated) | `samples/valid_token.txt...` |
| Algorithm | `HS256` |
| Type | `JWT` |
| Issuer | `https://auth.example.com` |
| Subject | `1234567890` |
| Audience | `https://api.example.com` |
| Expires At | `1781319622` |
| Issued At | `1781318722` |
| Signature Status | `Valid` |

---

## Risk Assessment

**Final Risk Level**: 🔵 **LOW**

> Low severity issues detected. Review recommendations for security improvements.

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 1 |
| 🔵 Low | 0 |
| ⚪ Info | 3 |
| **Total** | **4** |

---

## Security Findings

### 🟡 Medium Findings

#### [1] Algorithm 'HS256' Not in Allowed Algorithm List

| Field | Details |
|-------|---------|
| **Severity** | 🟡 Medium |
| **Confidence** | Potential |
| **Category** | Header |

**Evidence**
> Token uses alg='HS256'. Policy allowed_algorithms: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512']

**Impact**
> Using non-whitelisted algorithms may indicate misconfiguration or an attempt to exploit algorithm confusion vulnerabilities.

**Recommendation**
> Configure your JWT library to explicitly whitelist allowed algorithms. Never derive the algorithm from the token header.

---

### ⚪ Info Findings

#### [2] Token Expiration: Valid

| Field | Details |
|-------|---------|
| **Severity** | ⚪ Info |
| **Confidence** | Confirmed |
| **Category** | Claims |

**Evidence**
> 'exp' = 1781319622 | Expires in 10m 42s

**Impact**
> Token has not yet expired.

**Recommendation**
> Monitor token lifetime to ensure it aligns with policy.

---

#### [3] Issuer Identified: 'https://auth.example.com'

| Field | Details |
|-------|---------|
| **Severity** | ⚪ Info |
| **Confidence** | Informational |
| **Category** | Claims |

**Evidence**
> 'iss' = 'https://auth.example.com'

**Impact**
> Issuer claim is present.

**Recommendation**
> Issuer matches expected value.

---

#### [4] Signature Verification: VALID (HS256)

| Field | Details |
|-------|---------|
| **Severity** | ⚪ Info |
| **Confidence** | Confirmed |
| **Category** | Signature |

**Evidence**
> Algorithm: HS256 | HMAC signature verified successfully using the provided secret.

**Impact**
> Token signature is cryptographically valid with the provided key.

**Recommendation**
> Ensure the signing secret is rotated regularly and stored securely.

---

## Disclaimer

> ⚠ **Important**: This tool performs static JWT analysis and optional authorized endpoint
> testing only. All findings are indicators, not absolute proof, unless confirmed via
> signature verification or endpoint validation.
>
> This tool does not guarantee that the application is fully secure. It cannot assess
> all business logic, detect all BOLA/IDOR vulnerabilities, or replace manual penetration
> testing.
