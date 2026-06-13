#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jwt_analyzer.py
JWT Security Analyzer CLI — Main Entry Point

A terminal-only tool for defensive JWT security analysis.
Safe for public GitHub repositories. No brute force, no cracking,
no exploit automation, no unauthorized testing.

Usage:
  python jwt_analyzer.py --token "<jwt>"
  python jwt_analyzer.py --file token.txt
  python jwt_analyzer.py --token "<jwt>" --config configs/strict_policy.json
  python jwt_analyzer.py --token "<jwt>" --secret "mysecret"
  python jwt_analyzer.py --token "<jwt>" --public-key public.pem
  python jwt_analyzer.py --token "<jwt>" --endpoint "https://example.com/api"
  python jwt_analyzer.py --header-file request_headers.txt
  python jwt_analyzer.py --token "<jwt>" --output reports/report.json
  python jwt_analyzer.py --token "<jwt>" --markdown reports/report.md

Author  : nantzzsec
GitHub  : https://github.com/nantzzsec
License : MIT
"""

import sys
import os
import json
import argparse
import io

# Force UTF-8 output on Windows to handle Unicode characters
if sys.platform == 'win32':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except AttributeError:
        pass


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog='jwt_analyzer',
        description=(
            '🔐 JWT Security Analyzer CLI\n'
            'Defensive JWT analysis tool for authorized security assessments.\n\n'
            'DISCLAIMER: Use only on systems you are authorized to test.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python jwt_analyzer.py --token "eyJhbGc..."
  python jwt_analyzer.py --file token.txt --config configs/strict_policy.json
  python jwt_analyzer.py --token "eyJhbGc..." --secret "mysecret" --endpoint "https://api.example.com/me"
  python jwt_analyzer.py --header-file request.txt --markdown reports/report.md

Security Rules:
  - Only GET/HEAD requests are sent to endpoints
  - No brute force, wordlist cracking, or bypass generation
  - All endpoint testing assumes authorized access
  - Findings are indicators, not absolute proof
        """
    )

    # ── Input sources ─────────────────────────────────────────────────────────
    input_group = parser.add_argument_group('Input Sources (use one)')
    input_mutex = input_group.add_mutually_exclusive_group()
    input_mutex.add_argument(
        '--token', '-t',
        metavar='JWT',
        help='JWT token string (Bearer prefix is automatically stripped)'
    )
    input_mutex.add_argument(
        '--file', '-f',
        metavar='PATH',
        help='Path to a file containing the JWT token'
    )
    input_mutex.add_argument(
        '--header-file',
        metavar='PATH',
        help='Path to an HTTP request header file (extracts and analyzes JWTs from headers/cookies)'
    )

    # ── Configuration ─────────────────────────────────────────────────────────
    config_group = parser.add_argument_group('Configuration')
    config_group.add_argument(
        '--config', '-c',
        metavar='PATH',
        default=None,
        help='Path to policy config JSON file (default: configs/strict_policy.json if exists)'
    )

    # ── Verification ─────────────────────────────────────────────────────────
    verify_group = parser.add_argument_group('Signature Verification (Optional)')
    verify_group.add_argument(
        '--secret',
        metavar='SECRET',
        help='HMAC secret key for HS256/HS384/HS512 signature verification'
    )
    verify_group.add_argument(
        '--public-key',
        metavar='PATH',
        help='Path to PEM public key file for RS256/RS384/RS512/ES256/ES512 verification'
    )

    # ── Endpoint validation ───────────────────────────────────────────────────
    endpoint_group = parser.add_argument_group('Endpoint Validation (Optional, Authorized Testing Only)')
    endpoint_group.add_argument(
        '--endpoint', '-e',
        metavar='URL',
        help='Target endpoint URL to validate the token against (GET/HEAD only)'
    )
    endpoint_group.add_argument(
        '--tamper-check',
        action='store_true',
        default=False,
        help=(
            'Send a tampered token to check if the server validates signatures. '
            'Creates a Critical finding if tampered token is accepted.'
        )
    )
    endpoint_group.add_argument(
        '--method',
        metavar='METHOD',
        default='GET',
        choices=['GET', 'HEAD'],
        help='HTTP method for endpoint validation (default: GET)'
    )
    endpoint_group.add_argument(
        '--timeout',
        metavar='SECONDS',
        type=int,
        default=10,
        help='HTTP request timeout in seconds (default: 10)'
    )

    # ── Output ────────────────────────────────────────────────────────────────
    output_group = parser.add_argument_group('Output')
    output_group.add_argument(
        '--output', '-o',
        metavar='PATH',
        help='Export full report as JSON to the specified path'
    )
    output_group.add_argument(
        '--markdown', '-m',
        metavar='PATH',
        help='Export full report as Markdown to the specified path'
    )
    output_group.add_argument(
        '--quiet', '-q',
        action='store_true',
        default=False,
        help='Suppress terminal output (useful when only exporting to file)'
    )
    output_group.add_argument(
        '--no-info',
        action='store_true',
        default=False,
        help='Hide Info-level findings from terminal output'
    )

    # ── Version ───────────────────────────────────────────────────────────────
    parser.add_argument(
        '--version', '-v',
        action='version',
        version='jwt-security-analyzer-cli v1.0.0 by nantzzsec (github.com/nantzzsec)'
    )

    return parser


def load_policy(config_path: str) -> dict:
    """Load policy configuration from JSON file."""
    if not config_path:
        # Try default location
        default_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'configs', 'strict_policy.json'
        )
        if os.path.isfile(default_path):
            config_path = default_path
        else:
            return {}

    if not os.path.isfile(config_path):
        print(f"[!] Warning: Config file not found: {config_path}")
        return {}

    with open(config_path, 'r', encoding='utf-8') as f:
        try:
            policy = json.load(f)
            print(f"[✓] Loaded policy config: {config_path}")
            return policy
        except json.JSONDecodeError as e:
            print(f"[!] Warning: Failed to parse config JSON: {e}")
            return {}


def ensure_output_dir(filepath: str):
    """Create parent directories for output file if they don't exist."""
    parent = os.path.dirname(os.path.abspath(filepath))
    os.makedirs(parent, exist_ok=True)


def print_banner():
    """Print the CLI banner."""
    banner = """
+==================================================================+
| JWT Security Analyzer CLI  v1.0.0                                |
|  Author  : nantzzsec                                             |
|  GitHub  : https://github.com/nantzzsec                          |
|  License : MIT                                                   |
+==================================================================+
"""
    print(banner)


def main():
    """Main CLI entry point."""
    # Add project root to sys.path for module imports
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    from core.parser import (
        clean_token, read_token_from_file,
        detect_token_type, parse_jws,
        extract_tokens_from_header_file,
        JWTParseError
    )
    from core.header_analyzer import analyze_header
    from core.claim_analyzer import analyze_claims
    from core.signature_verifier import verify_signature
    from core.sensitive_detector import detect_sensitive_data
    from core.endpoint_validator import validate_endpoint
    from core.cookie_analyzer import analyze_headers_and_cookies
    from core.risk_engine import compute_risk
    from core.report_generator import (
        print_terminal_report, export_json, export_markdown
    )

    parser = build_parser()
    args = parser.parse_args()

    # ── Validate that at least one input is provided ──────────────────────────
    if not args.token and not args.file and not args.header_file:
        parser.print_help()
        print("\n[!] Error: Provide at least one input: --token, --file, or --header-file")
        sys.exit(1)

    if not args.quiet:
        print_banner()

    # ── Load policy config ────────────────────────────────────────────────────
    policy = load_policy(args.config)

    all_findings = []

    # ════════════════════════════════════════════════════════════════════════
    # MODE A: Header file analysis (--header-file)
    # ════════════════════════════════════════════════════════════════════════
    if args.header_file:
        print(f"[*] Analyzing header file: {args.header_file}")

        try:
            header_data = extract_tokens_from_header_file(args.header_file)
        except JWTParseError as e:
            print(f"[✗] Error reading header file: {e}")
            sys.exit(1)

        # Analyze headers and cookies
        header_cookie_findings = analyze_headers_and_cookies(header_data)
        all_findings.extend(header_cookie_findings)

        # Analyze each JWT found in Authorization header
        auth_tokens = header_data.get('authorization', [])
        for i, item in enumerate(auth_tokens):
            print(f"\n[*] Analyzing JWT #{i+1} from Authorization header...")
            token_str = item['token']
            _analyze_single_token(
                token_str, policy, args, all_findings,
                verify_signature, analyze_header, analyze_claims,
                detect_sensitive_data
            )

        # Analyze each JWT found in cookies
        for cookie in header_data.get('cookies', []):
            print(f"\n[*] Analyzing JWT from Cookie: {cookie['name']}...")
            _analyze_single_token(
                cookie['token'], policy, args, all_findings,
                verify_signature, analyze_header, analyze_claims,
                detect_sensitive_data
            )

        # Compute risk and show report
        if not all_findings:
            print("[i] No JWTs found in header file to analyze.")
            sys.exit(0)

        risk = compute_risk(all_findings)

        if not args.quiet:
            print_terminal_report(
                args.header_file, {}, {}, all_findings, risk, None
            )

        _export_outputs(args, {}, {}, all_findings, risk, None,
                        export_json, export_markdown)
        return

    # ════════════════════════════════════════════════════════════════════════
    # MODE B: Single token analysis (--token or --file)
    # ════════════════════════════════════════════════════════════════════════
    try:
        if args.token:
            raw_token = args.token
            token = clean_token(raw_token)
            print(f"[*] Analyzing token from --token argument...")
        else:
            token = read_token_from_file(args.file)
            print(f"[*] Analyzing token from file: {args.file}")
    except JWTParseError as e:
        print(f"[✗] Error reading token: {e}")
        sys.exit(1)

    # Detect token type
    token_type = detect_token_type(token)
    print(f"[*] Detected token type: {token_type}")

    if token_type == 'JWE':
        print("[i] JWE (encrypted) token detected. Full decryption not supported.")
        print("[i] Performing partial analysis on visible header only...")
        # JWE: only analyze the first part (header)
        try:
            from core.parser import decode_part
            jwe_header = decode_part(token.split('.')[0])
            header_findings = analyze_header(jwe_header, policy)
            all_findings.extend(header_findings)
            header = jwe_header
            payload = {}
        except JWTParseError as e:
            print(f"[!] Could not decode JWE header: {e}")
            sys.exit(1)
        sig_status = None

    elif token_type == 'JWS':
        try:
            header, payload, _ = parse_jws(token)
        except JWTParseError as e:
            print(f"[✗] Failed to parse JWT: {e}")
            sys.exit(1)

        # Run all analyzers
        print("[*] Running security checks...")

        # Header analysis
        header_findings = analyze_header(header, policy)
        all_findings.extend(header_findings)

        # Claims analysis
        claim_findings = analyze_claims(payload, policy)
        all_findings.extend(claim_findings)

        # Sensitive data detection
        sensitive_findings = detect_sensitive_data(payload, policy)
        all_findings.extend(sensitive_findings)

        # Signature verification
        sig_status = "Key Not Provided"
        if args.secret or args.public_key:
            print("[*] Verifying signature...")
            sig_status, sig_finding = verify_signature(
                token, header,
                secret=args.secret,
                public_key_path=args.public_key
            )
            all_findings.append(sig_finding)
            print(f"[*] Signature status: {sig_status}")

        # Endpoint validation
        if args.endpoint:
            print(f"\n[*] Validating endpoint: {args.endpoint}")
            print(f"[!] REMINDER: Ensure you are authorized to test this endpoint.")
            endpoint_findings = validate_endpoint(
                token=token,
                endpoint=args.endpoint,
                method=args.method,
                timeout=args.timeout,
                perform_tamper_check=args.tamper_check
            )
            all_findings.extend(endpoint_findings)

    else:
        print(f"[✗] Unrecognized token format. Expected 3 or 5 parts, got: {len(token.split('.'))} parts.")
        print("[i] Ensure the token is a valid JWS or JWE format.")
        sys.exit(1)

    # Compute risk score
    risk = compute_risk(all_findings)

    # Filter info findings from terminal if --no-info
    display_findings = all_findings
    if args.no_info:
        display_findings = [f for f in all_findings if f.severity != 'Info']
        from core.risk_engine import compute_risk as cr
        display_risk = cr(display_findings)
    else:
        display_risk = risk

    # Terminal output
    if not args.quiet:
        print_terminal_report(token, header, payload, display_findings, display_risk, sig_status)

    # File exports
    _export_outputs(args, header, payload, all_findings, risk, sig_status,
                    export_json, export_markdown)

    # Exit with non-zero code if Critical or High findings
    if risk['level'] in ('Critical', 'High'):
        sys.exit(2)


def _analyze_single_token(
    token: str, policy: dict, args, findings: list,
    verify_signature, analyze_header, analyze_claims,
    detect_sensitive_data
):
    """Analyze a single JWT token and append findings to the list."""
    from core.parser import detect_token_type, parse_jws, JWTParseError

    token_type = detect_token_type(token)
    if token_type != 'JWS':
        return

    try:
        header, payload, _ = parse_jws(token)
    except JWTParseError:
        return

    findings.extend(analyze_header(header, policy))
    findings.extend(analyze_claims(payload, policy))
    findings.extend(detect_sensitive_data(payload, policy))

    if args.secret or getattr(args, 'public_key', None):
        _, sig_finding = verify_signature(
            token, header,
            secret=getattr(args, 'secret', None),
            public_key_path=getattr(args, 'public_key', None)
        )
        findings.append(sig_finding)


def _export_outputs(args, header, payload, findings, risk, sig_status,
                    export_json, export_markdown):
    """Handle JSON and Markdown export if requested."""
    token_str = getattr(args, 'token', '') or getattr(args, 'file', '') or getattr(args, 'header_file', '') or ''

    if args.output:
        ensure_output_dir(args.output)
        export_json(token_str, header, payload, findings, risk, sig_status, args.output)

    if args.markdown:
        ensure_output_dir(args.markdown)
        export_markdown(token_str, header, payload, findings, risk, sig_status, args.markdown)


if __name__ == '__main__':
    main()
