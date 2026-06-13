"""
core/risk_engine.py
Risk Scoring Engine

Aggregates findings from all analyzers and computes a final risk score.

Risk scoring rules:
- Any Critical finding  → Final Risk: Critical
- Any High finding      → Final Risk: High
- Medium count >= 2     → Final Risk: Medium
- Only Low/Info         → Final Risk: Low
- No issues found       → Final Risk: Safe
"""

from typing import List, Dict
from core.header_analyzer import Finding


SEVERITY_ORDER = {
    'Critical': 5,
    'High': 4,
    'Medium': 3,
    'Low': 2,
    'Info': 1
}

RISK_COLORS = {
    'Critical': '\033[91m',   # Red
    'High': '\033[38;5;208m', # Orange
    'Medium': '\033[93m',     # Yellow
    'Low': '\033[94m',        # Blue
    'Safe': '\033[92m',       # Green
    'Info': '\033[96m',       # Cyan
}
RESET = '\033[0m'


def compute_risk(findings: List[Finding]) -> Dict:
    """
    Compute overall risk score from a list of findings.

    Args:
        findings: All findings from all analyzers

    Returns:
        Dict with keys:
            - level: 'Critical' | 'High' | 'Medium' | 'Low' | 'Safe'
            - counts: dict of {severity: count}
            - summary: human-readable summary string
            - findings_by_severity: grouped findings
    """
    counts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0,
        'Info': 0
    }

    findings_by_severity = {
        'Critical': [],
        'High': [],
        'Medium': [],
        'Low': [],
        'Info': []
    }

    for finding in findings:
        sev = finding.severity
        if sev in counts:
            counts[sev] += 1
            findings_by_severity[sev].append(finding)

    # ── Risk level determination ──────────────────────────────────────────────
    if counts['Critical'] > 0:
        level = 'Critical'
        summary = (
            f"{counts['Critical']} Critical issue(s) detected. "
            "Immediate remediation required."
        )
    elif counts['High'] > 0:
        level = 'High'
        summary = (
            f"{counts['High']} High severity issue(s) detected. "
            "Remediation strongly recommended."
        )
    elif counts['Medium'] >= 2:
        level = 'Medium'
        summary = (
            f"{counts['Medium']} Medium severity issue(s) detected. "
            "Review and remediate as part of normal security hardening."
        )
    elif counts['Medium'] == 1 or counts['Low'] > 0:
        level = 'Low'
        summary = (
            "Low severity issues detected. "
            "Review recommendations for security improvements."
        )
    else:
        level = 'Safe'
        summary = "No significant security issues detected in this token."

    return {
        'level': level,
        'counts': counts,
        'summary': summary,
        'findings_by_severity': findings_by_severity,
        'total_findings': len(findings)
    }


def get_severity_emoji(severity: str) -> str:
    """Return an emoji indicator for a severity level."""
    return {
        'Critical': '🔴',
        'High': '🟠',
        'Medium': '🟡',
        'Low': '🔵',
        'Info': '⚪',
        'Safe': '🟢'
    }.get(severity, '⚪')


def get_risk_badge(level: str) -> str:
    """Return a colored risk badge string."""
    emoji = get_severity_emoji(level)
    color = RISK_COLORS.get(level, '')
    return f"{color}{emoji} {level.upper()}{RESET}"
