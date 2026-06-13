"""
core/report_generator.py
Report Generation Module

Generates security analysis reports in:
- Terminal (rich colored output or plain text fallback)
- JSON export (--output)
- Markdown export (--markdown)
"""

import json
import datetime
from typing import Dict, List, Optional
from core.header_analyzer import Finding
from core.risk_engine import get_severity_emoji, get_risk_badge, RISK_COLORS, RESET

# Try to import rich for enhanced terminal output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info']


# ── Severity color map for plain output ─────────────────────────────────────
PLAIN_COLORS = {
    'Critical': '\033[91m',
    'High': '\033[38;5;208m',
    'Medium': '\033[93m',
    'Low': '\033[94m',
    'Info': '\033[96m',
}


def print_terminal_report(
    token: str,
    header: Dict,
    payload: Dict,
    findings: List[Finding],
    risk: Dict,
    sig_status: Optional[str] = None
):
    """
    Print a comprehensive security analysis report to the terminal.
    Uses rich if available, falls back to plain ANSI output.
    """
    if RICH_AVAILABLE:
        _print_rich_report(token, header, payload, findings, risk, sig_status)
    else:
        _print_plain_report(token, header, payload, findings, risk, sig_status)


def _print_rich_report(token, header, payload, findings, risk, sig_status):
    """Rich-formatted terminal report."""
    from rich.rule import Rule
    from rich.align import Align

    console.print()
    console.print(Rule("[bold cyan]🔐 JWT Security Analyzer[/bold cyan]", style="cyan"))
    console.print()

    # ── Token Info ────────────────────────────────────────────────────────────
    info_table = Table(box=box.ROUNDED, show_header=False, border_style="dim blue")
    info_table.add_column("Field", style="bold cyan", width=20)
    info_table.add_column("Value", style="white")

    truncated = token[:60] + '...' if len(token) > 60 else token
    info_table.add_row("Token (truncated)", truncated)
    info_table.add_row("Algorithm", str(header.get('alg', 'N/A')))
    info_table.add_row("Type", str(header.get('typ', 'N/A')))
    info_table.add_row("Subject", str(payload.get('sub', 'N/A')))
    info_table.add_row("Issuer", str(payload.get('iss', 'N/A')))
    info_table.add_row("Audience", str(payload.get('aud', 'N/A')))
    if sig_status:
        info_table.add_row("Signature Status", sig_status)

    console.print(Panel(info_table, title="[bold]Token Overview[/bold]", border_style="blue"))
    console.print()

    # ── Risk Score ────────────────────────────────────────────────────────────
    level = risk['level']
    counts = risk['counts']
    risk_style = {
        'Critical': 'bold red', 'High': 'bold yellow',
        'Medium': 'yellow', 'Low': 'cyan', 'Safe': 'bold green'
    }.get(level, 'white')

    risk_table = Table(box=box.SIMPLE, show_header=False)
    risk_table.add_column("", style="bold", width=20)
    risk_table.add_column("", style="white")

    emoji = get_severity_emoji(level)
    risk_table.add_row("Final Risk Level", f"[{risk_style}]{emoji} {level.upper()}[/{risk_style}]")
    risk_table.add_row("Summary", risk['summary'])
    risk_table.add_row(
        "Issue Counts",
        f"🔴 {counts['Critical']}  🟠 {counts['High']}  "
        f"🟡 {counts['Medium']}  🔵 {counts['Low']}  ⚪ {counts['Info']}"
    )

    console.print(Panel(risk_table, title="[bold]Risk Assessment[/bold]", border_style=risk_style))
    console.print()

    # ── Findings ──────────────────────────────────────────────────────────────
    console.print(Rule("[bold]Security Findings[/bold]", style="dim"))
    console.print()

    finding_count = 0
    for sev in SEVERITY_ORDER:
        sev_findings = risk['findings_by_severity'].get(sev, [])
        if not sev_findings:
            continue

        sev_style = {
            'Critical': 'bold red', 'High': 'bold yellow',
            'Medium': 'yellow', 'Low': 'cyan', 'Info': 'dim white'
        }.get(sev, 'white')

        emoji = get_severity_emoji(sev)
        console.print(f"[{sev_style}]{emoji} {sev.upper()} Findings ({len(sev_findings)})[/{sev_style}]")

        for f in sev_findings:
            finding_count += 1
            f_table = Table(box=box.MINIMAL, show_header=False, padding=(0, 1))
            f_table.add_column("Key", style="bold dim", width=18)
            f_table.add_column("Value", style="white")

            f_table.add_row("Confidence", f.confidence)
            f_table.add_row("Category", f.category)
            f_table.add_row("Evidence", f.evidence[:200] + '...' if len(f.evidence) > 200 else f.evidence)
            f_table.add_row("Impact", f.impact[:200] + '...' if len(f.impact) > 200 else f.impact)
            f_table.add_row("Recommendation", f.recommendation[:200] + '...' if len(f.recommendation) > 200 else f.recommendation)

            console.print(Panel(
                f_table,
                title=f"[{sev_style}][{finding_count}] {f.title}[/{sev_style}]",
                border_style=sev_style
            ))
            console.print()

    # ── Footer ────────────────────────────────────────────────────────────────
    console.print(Rule(style="dim"))
    console.print(
        "[dim]⚠ This tool performs static JWT analysis and authorized endpoint testing only.[/dim]"
    )
    console.print(
        "[dim]All findings are indicators, not absolute proof, unless Confirmed via verification.[/dim]"
    )
    console.print()


def _print_plain_report(token, header, payload, findings, risk, sig_status):
    """Plain ANSI terminal report fallback."""
    SEP = '─' * 70

    print(f"\n{'═' * 70}")
    print("  🔐 JWT Security Analyzer — Analysis Report")
    print(f"{'═' * 70}\n")

    # Token info
    print(f"  TOKEN (truncated): {token[:60]}...")
    print(f"  Algorithm : {header.get('alg', 'N/A')}")
    print(f"  Type      : {header.get('typ', 'N/A')}")
    print(f"  Subject   : {payload.get('sub', 'N/A')}")
    print(f"  Issuer    : {payload.get('iss', 'N/A')}")
    if sig_status:
        print(f"  Signature : {sig_status}")
    print()

    # Risk score
    level = risk['level']
    counts = risk['counts']
    color = RISK_COLORS.get(level, '')
    emoji = get_severity_emoji(level)
    print(f"{SEP}")
    print(f"  RISK LEVEL: {color}{emoji} {level.upper()}{RESET}")
    print(f"  {risk['summary']}")
    print(
        f"  🔴 Critical:{counts['Critical']}  "
        f"🟠 High:{counts['High']}  "
        f"🟡 Medium:{counts['Medium']}  "
        f"🔵 Low:{counts['Low']}  "
        f"⚪ Info:{counts['Info']}"
    )
    print(f"{SEP}\n")

    # Findings
    finding_count = 0
    for sev in SEVERITY_ORDER:
        sev_findings = risk['findings_by_severity'].get(sev, [])
        if not sev_findings:
            continue

        color = PLAIN_COLORS.get(sev, '')
        emoji = get_severity_emoji(sev)
        print(f"\n{color}{'─' * 60}{RESET}")
        print(f"{color}{emoji} {sev.upper()} FINDINGS ({len(sev_findings)}){RESET}")
        print(f"{color}{'─' * 60}{RESET}")

        for f in sev_findings:
            finding_count += 1
            print(f"\n  [{finding_count}] {color}{f.title}{RESET}")
            print(f"  {'─' * 50}")
            print(f"  Confidence     : {f.confidence}")
            print(f"  Category       : {f.category}")
            print(f"  Evidence       : {f.evidence[:150]}")
            print(f"  Impact         : {f.impact[:150]}")
            print(f"  Recommendation : {f.recommendation[:150]}")

    print(f"\n{'═' * 70}")
    print("  ⚠ This tool performs static analysis only. All findings are indicators.")
    print(f"{'═' * 70}\n")


def export_json(
    token: str,
    header: Dict,
    payload: Dict,
    findings: List[Finding],
    risk: Dict,
    sig_status: Optional[str],
    output_path: str
):
    """Export analysis results to JSON file."""
    report = {
        'tool': 'jwt-security-analyzer-cli',
        'version': '1.0.0',
        'generated_at': datetime.datetime.utcnow().isoformat() + 'Z',
        'token_overview': {
            'token_truncated': token[:60] + '...' if len(token) > 60 else token,
            'algorithm': header.get('alg'),
            'type': header.get('typ'),
            'issuer': payload.get('iss'),
            'subject': payload.get('sub'),
            'audience': payload.get('aud'),
            'expires_at': payload.get('exp'),
            'issued_at': payload.get('iat'),
            'signature_status': sig_status
        },
        'risk_assessment': {
            'level': risk['level'],
            'summary': risk['summary'],
            'counts': risk['counts'],
            'total_findings': risk['total_findings']
        },
        'findings': [
            {
                'title': f.title,
                'severity': f.severity,
                'confidence': f.confidence,
                'category': f.category,
                'evidence': f.evidence,
                'impact': f.impact,
                'recommendation': f.recommendation
            }
            for f in findings
        ]
    }

    with open(output_path, 'w', encoding='utf-8') as fp:
        json.dump(report, fp, indent=2, ensure_ascii=False)

    print(f"[✓] JSON report saved: {output_path}")


def export_markdown(
    token: str,
    header: Dict,
    payload: Dict,
    findings: List[Finding],
    risk: Dict,
    sig_status: Optional[str],
    output_path: str
):
    """Export analysis results to Markdown file."""
    now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    level = risk['level']
    counts = risk['counts']
    emoji = get_severity_emoji(level)

    lines = [
        "# 🔐 JWT Security Analysis Report",
        "",
        f"**Tool**: jwt-security-analyzer-cli v1.0.0  ",
        f"**Generated**: {now}",
        "",
        "---",
        "",
        "## Token Overview",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Token (truncated) | `{token[:60]}...` |",
        f"| Algorithm | `{header.get('alg', 'N/A')}` |",
        f"| Type | `{header.get('typ', 'N/A')}` |",
        f"| Issuer | `{payload.get('iss', 'N/A')}` |",
        f"| Subject | `{payload.get('sub', 'N/A')}` |",
        f"| Audience | `{payload.get('aud', 'N/A')}` |",
        f"| Expires At | `{payload.get('exp', 'N/A')}` |",
        f"| Issued At | `{payload.get('iat', 'N/A')}` |",
        f"| Signature Status | `{sig_status or 'Not checked'}` |",
        "",
        "---",
        "",
        "## Risk Assessment",
        "",
        f"**Final Risk Level**: {emoji} **{level.upper()}**",
        "",
        f"> {risk['summary']}",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 Critical | {counts['Critical']} |",
        f"| 🟠 High | {counts['High']} |",
        f"| 🟡 Medium | {counts['Medium']} |",
        f"| 🔵 Low | {counts['Low']} |",
        f"| ⚪ Info | {counts['Info']} |",
        f"| **Total** | **{risk['total_findings']}** |",
        "",
        "---",
        "",
        "## Security Findings",
        "",
    ]

    finding_count = 0
    for sev in SEVERITY_ORDER:
        sev_findings = risk['findings_by_severity'].get(sev, [])
        if not sev_findings:
            continue

        sev_emoji = get_severity_emoji(sev)
        lines.append(f"### {sev_emoji} {sev} Findings")
        lines.append("")

        for f in sev_findings:
            finding_count += 1
            lines += [
                f"#### [{finding_count}] {f.title}",
                "",
                f"| Field | Details |",
                f"|-------|---------|",
                f"| **Severity** | {sev_emoji} {f.severity} |",
                f"| **Confidence** | {f.confidence} |",
                f"| **Category** | {f.category} |",
                "",
                "**Evidence**",
                f"> {f.evidence}",
                "",
                "**Impact**",
                f"> {f.impact}",
                "",
                "**Recommendation**",
                f"> {f.recommendation}",
                "",
                "---",
                "",
            ]

    lines += [
        "## Disclaimer",
        "",
        "> ⚠ **Important**: This tool performs static JWT analysis and optional authorized endpoint",
        "> testing only. All findings are indicators, not absolute proof, unless confirmed via",
        "> signature verification or endpoint validation.",
        ">",
        "> This tool does not guarantee that the application is fully secure. It cannot assess",
        "> all business logic, detect all BOLA/IDOR vulnerabilities, or replace manual penetration",
        "> testing.",
        "",
    ]

    with open(output_path, 'w', encoding='utf-8') as fp:
        fp.write('\n'.join(lines))

    print(f"[✓] Markdown report saved: {output_path}")
