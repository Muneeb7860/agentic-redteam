"""
agentic_redteam.sarif_exporter — SARIF v2.1.0 Exporter

Produces a Static Analysis Results Interchange Format (SARIF) v2.1.0 JSON file
compatible with GitHub Code Scanning, VS Code SARIF Viewer, and SonarQube.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentic_redteam.scoring import OWASPScore, CategoryScore

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "agentic-redteam"
TOOL_VERSION = "1.0.0"
TOOL_URI = "https://swishos.dev"

# OWASP LLM Top 10 + ASI rule definitions
OWASP_RULES: dict[str, dict[str, str]] = {
    "prompt_injection":   {"id": "LLM01", "name": "PromptInjection",      "shortDesc": "LLM01 Prompt Injection",            "level": "error"},
    "indirect_injection": {"id": "LLM02", "name": "IndirectInjection",    "shortDesc": "LLM02 Indirect Prompt Injection",    "level": "error"},
    "pii_leakage":        {"id": "LLM06", "name": "PIILeakage",           "shortDesc": "LLM06 Sensitive Information Disclosure", "level": "error"},
    "jailbreak":          {"id": "LLM01", "name": "Jailbreak",            "shortDesc": "LLM01 Prompt Injection — Jailbreak", "level": "error"},
    "action_level":       {"id": "LLM08", "name": "ExcessiveAgency",      "shortDesc": "LLM08 Excessive Agency",             "level": "error"},
    "multi_turn":         {"id": "ASI01", "name": "MultiTurnASTSplitting","shortDesc": "ASI01 Multi-Turn AST Payload Splitting", "level": "error"},
    "centroid_probes":    {"id": "LLM07", "name": "CentroidAnchor",       "shortDesc": "LLM07 System Prompt Leakage",        "level": "error"},
    "crypto_probes":      {"id": "ASI09", "name": "CryptoProbe",          "shortDesc": "ASI09 Crypto Side-Channel Probe",    "level": "error"},
    "code_safety":        {"id": "LLM03", "name": "CodeSafety",           "shortDesc": "LLM03 Training Data Poisoning",      "level": "warning"},
    "schema_compliance":  {"id": "LLM10", "name": "SchemaCompliance",     "shortDesc": "LLM10 Model Denial of Service",      "level": "warning"},
    "clean_queries":      {"id": "LLM05", "name": "CleanQueries",         "shortDesc": "LLM05 Output Handling Regression",   "level": "note"},
}

LEVEL_MAP = {"error": "error", "warning": "warning", "note": "note"}


def _build_rules() -> list[dict[str, Any]]:
    seen: set[str] = set()
    rules = []
    for cat, info in OWASP_RULES.items():
        rule_id = f"{info['id']}/{cat}"
        if rule_id in seen:
            continue
        seen.add(rule_id)
        rules.append({
            "id": rule_id,
            "name": info["name"],
            "shortDescription": {"text": info["shortDesc"]},
            "fullDescription": {"text": f"SwishOS agentic-redteam scanner detected failures in category: {cat}"},
            "helpUri": f"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "properties": {
                "owaspCategory": info["id"],
                "severity": info["level"],
            },
        })
    return rules


def _category_to_result(cat_score: CategoryScore, target_url: str) -> dict[str, Any] | None:
    """Return a SARIF result for a failed category, or None if passing."""
    if cat_score.failed == 0:
        return None

    info = OWASP_RULES.get(cat_score.category, {
        "id": "CUSTOM",
        "name": cat_score.category,
        "shortDesc": cat_score.category,
        "level": "warning",
    })
    rule_id = f"{info['id']}/{cat_score.category}"
    level = LEVEL_MAP.get(info["level"], "warning")

    return {
        "ruleId": rule_id,
        "level": level,
        "message": {
            "text": (
                f"{info['shortDesc']}: {cat_score.failed}/{cat_score.total} tests failed "
                f"(weighted penalty: {cat_score.weighted_penalty}, pass rate: {cat_score.pass_rate}%)"
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": target_url,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": 1},
                }
            }
        ],
        "properties": {
            "category": cat_score.category,
            "passed": cat_score.passed,
            "failed": cat_score.failed,
            "total": cat_score.total,
            "weightedPenalty": cat_score.weighted_penalty,
        },
    }


def export_sarif(
    score: OWASPScore,
    target_url: str,
    output_path: str | Path = "agentic-redteam.sarif",
) -> Path:
    """
    Export SARIF v2.1.0 report from an OWASPScore.

    Args:
        score: Computed OWASPScore from compute_owasp_score()
        target_url: The scanned endpoint URL (used as artifact URI in SARIF)
        output_path: Destination file path for the .sarif file

    Returns:
        Resolved Path to the written SARIF file.
    """
    results = []
    for cat_score in score.breakdown.values():
        result = _category_to_result(cat_score, target_url)
        if result:
            results.append(result)

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": _build_rules(),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": f"agentic-redteam --target-url {target_url} --format sarif",
                        "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                        "properties": {
                            "compositeScore": score.composite,
                            "grade": score.grade,
                            "totalTests": score.total_tests,
                            "totalPassed": score.total_passed,
                            "totalFailed": score.total_failed,
                            "overallPassRate": score.overall_pass_rate,
                        },
                    }
                ],
            }
        ],
    }

    out = Path(output_path)
    out.write_text(json.dumps(sarif_doc, indent=2))
    return out
