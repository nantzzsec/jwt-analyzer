# 🔐 JWT Security Analyzer CLI

> **Author**: [nantzzsec](https://github.com/nantzzsec)  
> **GitHub**: https://github.com/nantzzsec/jwt-analyzer 
> **License**: MIT

A terminal-only, defensive JWT security analysis tool built in Python.
Safe for public GitHub repositories. No brute force. No cracking. No unauthorized testing.

---

## ✨ Features

| Category | Capabilities |
|---|---|
| **Input Handling** | `--token`, `--file`, `--header-file`; auto-strips Bearer prefix |
| **Token Detection** | JWS (3 parts) and JWE (5 parts) detection |
| **Header Analysis** | `alg: none`, missing alg, allowed algorithms policy, `kid` injection, `jku`/`x5u` SSRF |
| **Claims Analysis** | `exp`, `iat`, `nbf`, `iss`, `aud`, `sub`, `jti`; lifetime checks; future `iat` |
| **Sensitive Data** | Keyword matching, regex patterns, Shannon entropy analysis |
| **Signature Verify** | HMAC (HS256/384/512) and RSA/EC (RS256/384/512, ES256/384/512) |
| **Endpoint Validation** | Authorized GET/HEAD testing; tamper check for signature enforcement |
| **Header/Cookie Audit** | HttpOnly, Secure, SameSite; JWT-in-URL detection |
| **Risk Scoring** | Critical → High → Medium → Low → Safe aggregated scoring |
| **Reporting** | Terminal (rich/ANSI), JSON export, Markdown export |
| **Policy Config** | JSON-based expected issuer, audience, required claims, max lifetime |

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/nantzzsec/jwt-analyzer.git
cd jwt-analyzer
```

### 2. Create virtual environment (recommended)

```bash
python -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 3. Install dependencies

```bash
# Full install (with rich UI and crypto verification)
pip install -r requirements.txt

# Minimal install — runs with Python stdlib only
# (no pip install needed)
```

> **Note**: The tool works with zero dependencies using Python 3.6+ standard library.
> Optional packages (`rich`, `cryptography`) enhance terminal output and signature verification.

---

## 🚀 Usage

### Basic Token Analysis

```bash
python jwt_analyzer.py --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abc"
```

### Analyze from File

```bash
python jwt_analyzer.py --file samples/valid_token.txt
```

### Use a Policy Config

```bash
python jwt_analyzer.py --token "<jwt>" --config configs/strict_policy.json
```

### Verify HMAC Signature

```bash
python jwt_analyzer.py --token "<jwt>" --secret "your-secret-key"
```

### Verify RSA/EC Signature

```bash
python jwt_analyzer.py --token "<jwt>" --public-key public.pem
```

### Endpoint Validation (Authorized Testing Only)

```bash
python jwt_analyzer.py --token "<jwt>" --endpoint "https://api.example.com/me"
```

### Tamper Check (Detect Missing Signature Validation)

```bash
python jwt_analyzer.py --token "<jwt>" --endpoint "https://api.example.com/me" --tamper-check
```

### Analyze HTTP Request Headers

```bash
python jwt_analyzer.py --header-file samples/sample_request_headers.txt
```

### Export Reports

```bash
# JSON export
python jwt_analyzer.py --token "<jwt>" --output reports/report.json

# Markdown export
python jwt_analyzer.py --token "<jwt>" --markdown reports/report.md

# Both exports + suppress terminal output
python jwt_analyzer.py --token "<jwt>" --output reports/report.json --markdown reports/report.md --quiet
```

### Hide Info-Level Findings

```bash
python jwt_analyzer.py --token "<jwt>" --no-info
```

---

## 📋 All CLI Commands

| Command | Description |
|---|---|
| `--token <jwt>` | JWT token string (Bearer prefix auto-removed) |
| `--file <path>` | Read JWT from a text file |
| `--header-file <path>` | Analyze HTTP request header file |
| `--config <path>` | Policy config JSON file |
| `--secret <key>` | HMAC secret for signature verification |
| `--public-key <path>` | PEM public key for RSA/EC verification |
| `--endpoint <url>` | Endpoint URL for authorized validation |
| `--tamper-check` | Send corrupted token to test signature enforcement |
| `--method GET\|HEAD` | HTTP method (default: GET) |
| `--timeout <sec>` | Request timeout seconds (default: 10) |
| `--output <path>` | Export JSON report |
| `--markdown <path>` | Export Markdown report |
| `--quiet` | Suppress terminal output |
| `--no-info` | Hide Info-level findings |
| `--version` | Show version |

---

## 📊 Example Output

```
╔══════════════════════════════════════════════════════════════════╗
║           🔐  JWT Security Analyzer CLI  v1.0.0                 ║
║    Defensive JWT Analysis — Safe for Public GitHub Repos        ║
╚══════════════════════════════════════════════════════════════════╝

[*] Analyzing token from --token argument...
[*] Detected token type: JWS
[*] Running security checks...

══════════════════════════════════════════════════════════════
  TOKEN   : eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0...
  Alg     : none
  Risk    : 🔴 CRITICAL
══════════════════════════════════════════════════════════════

🔴 CRITICAL FINDINGS (1)
──────────────────────────────────────────────────────────────
  [1] Algorithm Set to 'none' — Signature Bypass Risk
  ────────────────────────────────────────────
  Confidence     : Confirmed
  Evidence       : 'alg' field value: 'none'
  Impact         : Tokens using 'alg: none' carry no cryptographic signature...
  Recommendation : Reject all tokens with alg=none on the server side...
```

---

## ⚙️ Policy Config Example

Create or edit `configs/strict_policy.json`:

```json
{
  "expected_issuer": "https://auth.example.com",
  "expected_audience": "https://api.example.com",
  "required_claims": ["sub", "iat", "exp", "jti"],
  "allowed_algorithms": ["RS256", "RS384", "ES256", "ES512"],
  "max_lifetime_minutes": 60,
  "sensitive_keywords": [
    "password", "secret", "api_key", "private_key",
    "refresh_token", "client_secret"
  ]
}
```

| Field | Type | Description |
|---|---|---|
| `expected_issuer` | string | Expected `iss` claim value |
| `expected_audience` | string | Expected `aud` claim value |
| `required_claims` | array | Claims that must be present |
| `allowed_algorithms` | array | Whitelist of allowed algorithms |
| `max_lifetime_minutes` | integer | Maximum token lifetime in minutes |
| `sensitive_keywords` | array | Additional keywords to flag in payload |

---

## 🔍 Finding Severity Levels

| Level | Emoji | Description |
|---|---|---|
| **Critical** | 🔴 | Confirmed severe vulnerability (e.g., alg=none, tamper accepted) |
| **High** | 🟠 | Likely vulnerability needing immediate attention |
| **Medium** | 🟡 | Security weakness that should be addressed |
| **Low** | 🔵 | Minor issue or hardening recommendation |
| **Info** | ⚪ | Informational, no immediate risk |

### Risk Score Aggregation

| Condition | Final Risk |
|---|---|
| Any Critical finding | 🔴 **Critical** |
| Any High finding | 🟠 **High** |
| Medium count ≥ 2 | 🟡 **Medium** |
| Only Low/Info | 🔵 **Low** |
| No issues | 🟢 **Safe** |

---

## 🧪 Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Or with stdlib unittest
python -m unittest discover tests/ -v

# Run specific test module
python -m unittest tests.test_parser -v
python -m unittest tests.test_header_analyzer -v
python -m unittest tests.test_risk_engine -v
```

---

## 📁 Project Structure

```
jwt-security-analyzer-cli/
├── jwt_analyzer.py             # Main CLI entry point
├── core/
│   ├── __init__.py
│   ├── parser.py               # Token parsing and input handling
│   ├── header_analyzer.py      # JWT header security analysis
│   ├── claim_analyzer.py       # JWT claims/payload analysis
│   ├── signature_verifier.py   # HMAC and RSA/EC verification
│   ├── sensitive_detector.py   # Sensitive data detection
│   ├── endpoint_validator.py   # Authorized endpoint validation
│   ├── cookie_analyzer.py      # HTTP header/cookie analysis
│   ├── risk_engine.py          # Risk scoring aggregation
│   └── report_generator.py     # Terminal/JSON/Markdown reports
├── configs/
│   └── strict_policy.json      # Security policy configuration
├── samples/
│   ├── valid_token.txt         # Valid HS256 token (15min exp)
│   ├── expired_token.txt       # Expired token
│   ├── none_alg_token.txt      # alg=none token (critical)
│   ├── missing_exp_token.txt   # Token without exp claim
│   └── sample_request_headers.txt  # HTTP request header file
├── reports/                    # Generated reports (gitignored)
├── tests/
│   ├── __init__.py
│   ├── test_parser.py
│   ├── test_header_analyzer.py
│   └── test_risk_engine.py
├── requirements.txt
├── README.md
└── LICENSE
```

---

## ⚠️ Security Disclaimer

This tool is designed **exclusively** for:
- Static analysis of JWT tokens you own or are authorized to test
- Security assessments on systems with explicit written permission
- Educational purposes and learning JWT security concepts

**This tool does NOT and will NOT:**
- 🚫 Perform JWT secret brute force or wordlist cracking
- 🚫 Generate bypass tokens or exploit payloads
- 🚫 Perform mass endpoint scanning or fuzzing
- 🚫 Send any HTTP request method other than GET/HEAD by default
- 🚫 Store or transmit any token data externally

**All findings are indicators, not absolute proof**, unless confirmed through:
- Cryptographic signature verification (`--secret` or `--public-key`)
- Authorized endpoint validation (`--endpoint` with `--tamper-check`)

**Unauthorized use of this tool against systems you do not own or have explicit permission to test is illegal and unethical.**

---

## ⚡ Limitations

This tool performs **static JWT analysis** and **optional authorized endpoint validation**.

It **cannot**:
- Guarantee that the overall application is fully secure
- Understand all application-specific business logic
- Detect all BOLA (Broken Object Level Authorization) or IDOR vulnerabilities
- Confirm complete token revocation without backend context
- Replace manual penetration testing or a full security audit
- Detect server-side misconfigurations beyond what is visible in the token
- Analyze encrypted JWT (JWE) payload content
- Assess rate limiting, account lockout, or session management policies

**Always combine this tool with:**
- Manual code review
- Authenticated penetration testing
- Dynamic application security testing (DAST)
- Professional security audit for production systems

---

## 🗺️ Roadmap

- [ ] **v1.1** — JWT library fingerprinting based on claim patterns
- [ ] **v1.2** — JWKS (JSON Web Key Set) URL fetcher and key validation
- [ ] **v1.3** — Batch analysis mode for multiple tokens from a file
- [ ] **v1.4** — HTML report export
- [ ] **v1.5** — Token comparison mode (diff two tokens)
- [ ] **v2.0** — Plugin architecture for custom analyzers
- [ ] **v2.1** — CI/CD integration mode (structured JSON output, strict exit codes)

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork from: https://github.com/nantzzsec/jwt-security-analyzer-cli
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Follow existing code style (docstrings, type hints, modular design)
4. Add unit tests for new functionality
5. Ensure all existing tests pass: `python -m unittest discover tests/ -v`
6. Submit a pull request to `nantzzsec/jwt-analyzer`

**Important**: Do not submit contributions that add brute force, cracking, exploit generation, or any offensive capability.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built by [nantzzsec](https://github.com/nantzzsec) for defensive security analysis. Use responsibly.*
