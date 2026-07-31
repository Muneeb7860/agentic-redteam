"""PDF Report Generator — executive audit summary for CISO delivery.

Generates a clean text report (and optionally PDF via weasyprint if installed)
with: executive summary, OWASP scorecard, per-category breakdown, failure
details, before/after comparison, and recommendations.

Usage:
    from agentic_redteam.report_generator import generate_report

    generate_report(
        app_name="payment-agent",
        results=results_dict,
        output_path="audit_report.md",
        previous_results=prev_dict,  # optional, for before/after
    )
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def generate_report(
    app_name: str,
    results: dict[str, Any],
    output_path: str | Path = "audit_report.md",
    previous_results: dict[str, Any] | None = None,
    client_name: str = "Client",
    auditor_name: str = "SwishOS Security Research",
) -> Path:
    """Generate a markdown audit report. Returns the output path."""
    output = Path(output_path)
    owasp = results.get("owasp_score", {})
    summary = results.get("summary", {})
    failures = results.get("failures", [])
    elapsed = results.get("elapsed_seconds", 0)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    grade = owasp.get("grade", "?")
    score = owasp.get("composite", 0)
    pass_rate = owasp.get("pass_rate", 0)
    total_tests = owasp.get("total_tests", 0)
    total_passed = owasp.get("total_passed", 0)

    lines = []
    lines.append(f"# AI Agent Security Audit Report")
    lines.append(f"")
    lines.append(f"**Client:** {client_name}")
    lines.append(f"**Target:** {app_name}")
    lines.append(f"**Auditor:** {auditor_name}")
    lines.append(f"**Date:** {now}")
    lines.append(f"**Tool:** agentic-redteam v1.0.0")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    # Executive Summary
    lines.append(f"## Executive Summary")
    lines.append(f"")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| **OWASP Composite Score** | **{score}/100** |")
    lines.append(f"| **Grade** | **{grade}** |")
    lines.append(f"| **Pass Rate** | {pass_rate}% ({total_passed}/{total_tests}) |")
    lines.append(f"| **Categories Tested** | {len(summary)} |")
    lines.append(f"| **Total Payloads** | {total_tests} |")
    lines.append(f"| **Failures** | {len(failures)} |")
    lines.append(f"| **Evaluation Time** | {elapsed:.1f}s |")
    lines.append(f"")

    # Grade interpretation
    if grade == "A":
        lines.append(f"> **Grade A** — All tested attack vectors are defended. The system demonstrates comprehensive guardrail coverage across all evaluated OWASP categories.")
    elif grade == "B":
        lines.append(f"> **Grade B** — Strong coverage with minor gaps. {len(failures)} finding(s) require remediation before production certification.")
    elif grade == "C":
        lines.append(f"> **Grade C** — Moderate coverage. Multiple gaps identified that present material risk in a production deployment.")
    else:
        lines.append(f"> **Grade {grade}** — Significant gaps. Immediate remediation required before production use.")
    lines.append(f"")

    # Before/After Comparison
    if previous_results:
        prev_owasp = previous_results.get("owasp_score", {})
        prev_rate = prev_owasp.get("pass_rate", 0)
        prev_score = prev_owasp.get("composite", 0)
        prev_failures = previous_results.get("failures", [])

        delta_rate = pass_rate - prev_rate
        delta_score = score - prev_score
        fixed = len(prev_failures) - len(failures)

        lines.append(f"## Before / After Comparison")
        lines.append(f"")
        lines.append(f"| Metric | Previous | Current | Change |")
        lines.append(f"|--------|----------|---------|--------|")
        lines.append(f"| Pass Rate | {prev_rate}% | {pass_rate}% | {'+' if delta_rate >= 0 else ''}{delta_rate:.1f}% |")
        lines.append(f"| OWASP Score | {prev_score}/100 | {score}/100 | {'+' if delta_score >= 0 else ''}{delta_score} |")
        lines.append(f"| Grade | {prev_owasp.get('grade', '?')} | {grade} | {'Improved' if delta_score > 0 else 'Unchanged' if delta_score == 0 else 'Regressed'} |")
        lines.append(f"| Open Findings | {len(prev_failures)} | {len(failures)} | {'+' if fixed < 0 else ''}{-fixed if fixed != 0 else '—'} |")
        lines.append(f"")
        if fixed > 0:
            lines.append(f"> **{fixed} finding(s) fixed** since the previous audit run.")
        lines.append(f"")

    # Category Breakdown
    lines.append(f"## Category Breakdown")
    lines.append(f"")
    lines.append(f"| Category | Passed | Total | Rate | Status |")
    lines.append(f"|----------|--------|-------|------|--------|")
    for cat, data in sorted(summary.items()):
        p = data.get("passed", 0)
        t = data.get("total", 0)
        r = data.get("pass_rate", 0)
        status = "PASS" if r == 100 else "FAIL"
        icon = "pass" if r == 100 else "**FAIL**"
        lines.append(f"| {cat} | {p} | {t} | {r}% | {icon} |")
    lines.append(f"")

    # Failures Detail
    if failures:
        lines.append(f"## Findings ({len(failures)})")
        lines.append(f"")
        for i, f in enumerate(failures, 1):
            cat = f.get("category", "unknown")
            desc = f.get("description", "No description")
            query = f.get("query", "")
            lines.append(f"### Finding {i}: {desc}")
            lines.append(f"")
            lines.append(f"- **Category:** {cat}")
            lines.append(f"- **Severity:** Critical (attack payload not blocked)")
            lines.append(f"- **Payload:**")
            lines.append(f"  ```")
            lines.append(f"  {query[:200]}")
            lines.append(f"  ```")
            lines.append(f"- **Recommendation:** Add guardrail coverage for this attack class. Re-test after fix to confirm resolution.")
            lines.append(f"")
    else:
        lines.append(f"## Findings")
        lines.append(f"")
        lines.append(f"No findings. All {total_tests} attack payloads were correctly defended.")
        lines.append(f"")

    # Recommendations
    lines.append(f"## Recommendations")
    lines.append(f"")
    if grade == "A":
        lines.append(f"1. Maintain current guardrail coverage with scheduled weekly re-audits.")
        lines.append(f"2. Add the new ASI04 (sandbox escape) and ASI10 (rogue persistence) categories to your CI gate.")
        lines.append(f"3. Consider a retainer engagement for continuous monitoring ($4,500/mo).")
    else:
        lines.append(f"1. **Immediate:** Remediate the {len(failures)} open finding(s) listed above.")
        lines.append(f"2. **Short-term:** Re-run this audit after fixes to confirm Grade A.")
        lines.append(f"3. **Ongoing:** Add `agentic-redteam --ci` to your deployment pipeline as a gate.")
        lines.append(f"4. **Advisory:** Consider a SwishOS retainer for continuous governance monitoring.")
    lines.append(f"")

    # Footer
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"*Generated by agentic-redteam v1.0.0 | SwishOS Security Research*")
    lines.append(f"*Report format: Markdown (convert to PDF via pandoc or weasyprint)*")
    lines.append(f"*Contact: security@swishos.io | https://swishos.io/en/contact?plan=audit*")

    content = "\n".join(lines)
    output.write_text(content + "\n")
    return output
