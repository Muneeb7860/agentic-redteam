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
from agentic_redteam.remediation import get_remediation

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "agentic-redteam"
TOOL_VERSION = "1.0.0"
TOOL_URI = "https://swishos.dev"

# OWASP LLM Top 10 + ASI rule definitions
OWASP_RULES: dict[str, dict[str, str]] = {
    "prompt_injection":         {"id": "LLM01", "name": "PromptInjection",            "shortDesc": "LLM01 Prompt Injection",                  "level": "error"},
    "indirect_injection":       {"id": "LLM02", "name": "IndirectInjection",          "shortDesc": "LLM02 Indirect Prompt Injection",          "level": "error"},
    "pii_leakage":              {"id": "LLM06", "name": "PIILeakage",                 "shortDesc": "LLM06 Sensitive Information Disclosure",   "level": "error"},
    "jailbreak":                {"id": "LLM01", "name": "Jailbreak",                  "shortDesc": "LLM01 Prompt Injection — Jailbreak",       "level": "error"},
    "action_level":             {"id": "LLM08", "name": "ExcessiveAgency",            "shortDesc": "LLM08 Excessive Agency",                   "level": "error"},
    "mcp_security":             {"id": "ASI06", "name": "MCPToolPoisoning",           "shortDesc": "ASI06 MCP Tool Poisoning & Unauthorized Tool Execution", "level": "error"},
    "multi_turn":               {"id": "ASI01", "name": "MultiTurnASTSplitting",      "shortDesc": "ASI01 Multi-Turn AST Payload Splitting",   "level": "error"},
    "centroid_probes":          {"id": "LLM07", "name": "CentroidAnchor",             "shortDesc": "LLM07 System Prompt Leakage",              "level": "error"},
    "crypto_probes":            {"id": "ASI09", "name": "CryptoProbe",                "shortDesc": "ASI09 Crypto Side-Channel Probe",          "level": "error"},
    "asi04_sandbox_escape":     {"id": "ASI04", "name": "SandboxEscape",              "shortDesc": "ASI04 Sandbox Escape & Proxy Exploitation", "level": "error"},
    "asi10_rogue_persistence":  {"id": "ASI10", "name": "RogueAgentPersistence",     "shortDesc": "ASI10 Rogue Agent Persistence & Drift",    "level": "error"},
    "ssrf":                     {"id": "LLM02", "name": "SSRF",                       "shortDesc": "LLM02 Server-Side Request Forgery & Metadata Access", "level": "error"},
    "tool_orchestration_abuse": {"id": "ASI06", "name": "ToolOrchestrationAbuse",    "shortDesc": "ASI06 Unsafe Tool Composition & Budget Exhaustion", "level": "error"},
    "autonomous_agent_drift":   {"id": "ASI10", "name": "AutonomousAgentDrift",       "shortDesc": "ASI10 Autonomous Agent Drift & Runaway Behavior", "level": "error"},
    "cross_context_retrieval":  {"id": "LLM02", "name": "CrossContextRetrieval",      "shortDesc": "LLM02 Multi-Tenant Cross-Context Leakage", "level": "error"},
    "code_safety":              {"id": "LLM03", "name": "CodeSafety",                 "shortDesc": "LLM03 Insecure Code Execution",           "level": "warning"},
    "schema_compliance":        {"id": "LLM10", "name": "SchemaCompliance",           "shortDesc": "LLM10 Model Denial of Service / Schema",   "level": "warning"},
    "clean_queries":            {"id": "LLM05", "name": "CleanQueries",               "shortDesc": "LLM05 Output Handling Regression",         "level": "note"},
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
        rem = get_remediation(cat)
        help_markdown = (
            f"**Root cause:** {rem.root_cause}\n\n"
            f"**Recommended fix:**\n"
            + "\n".join(f"- {step}" for step in rem.fix_steps)
        )
        rules.append({
            "id": rule_id,
            "name": info["name"],
            "shortDescription": {"text": info["shortDesc"]},
            "fullDescription": {"text": f"SwishOS agentic-redteam scanner detected failures in category: {cat}"},
            "helpUri": rem.references[0] if rem.references else "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "help": {
                "text": f"{rem.root_cause} Fix: {' '.join(rem.fix_steps)}",
                "markdown": help_markdown,
            },
            "properties": {
                "owaspCategory": info["id"],
                "severity": info["level"],
                "control": rem.control,
                "references": rem.references,
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
    rem = get_remediation(cat_score.category)

    return {
        "ruleId": rule_id,
        "level": level,
        "message": {
            "text": (
                f"{info['shortDesc']}: {cat_score.failed}/{cat_score.total} tests failed "
                f"(weighted penalty: {cat_score.weighted_penalty}, pass rate: {cat_score.pass_rate}%). "
                f"Root cause: {rem.root_cause} "
                f"Fix: {' '.join(rem.fix_steps)}"
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
            "control": rem.control,
            "rootCause": rem.root_cause,
            "fixSteps": rem.fix_steps,
            "references": rem.references,
        },
    }


TRACE_RULES: dict[str, dict[str, str]] = {
    "split_transaction":      {"id": "ASI01", "name": "ToolSplitTransaction",     "shortDesc": "ASI01 Incremental Limit Bypass via Split Tool Calls", "level": "error"},
    "subagent_amplification": {"id": "ASI06", "name": "SubagentAmplification",    "shortDesc": "ASI06 Recursive Sub-Agent Spawn & Amplification",      "level": "error"},
    "state_tampering":        {"id": "ASI10", "name": "AgentDriftStateTampering", "shortDesc": "ASI10 System Prompt & Governance State Tampering",     "level": "error"},
    "cross_tenant_leak":      {"id": "LLM02", "name": "MultiTenantLeakage",       "shortDesc": "LLM02 Unauthorized Cross-Tenant Namespace Access",    "level": "error"},
    "refusal_bypass":         {"id": "LLM08", "name": "SiblingToolBypass",        "shortDesc": "LLM08 Refused Action Achieved via Sibling Capability", "level": "error"},
    "unguarded_sibling":      {"id": "LLM08", "name": "UnguardedSiblingTool",     "shortDesc": "LLM08 Uncapped Action via Unguarded Sibling Tool",     "level": "error"},
    "path_traversal":         {"id": "LLM03", "name": "PathTraversal",            "shortDesc": "LLM03 Filesystem Scope Boundary Traversal",            "level": "error"},
    "exfiltration_chain":     {"id": "LLM06", "name": "ExfiltrationChain",        "shortDesc": "LLM06 Multi-Tool Data Exfiltration Chain",            "level": "error"},
}


def _trace_finding_to_result(finding: dict[str, Any], target_url: str) -> dict[str, Any]:
    kind = finding.get("kind", "unknown")
    info = TRACE_RULES.get(kind, {
        "id": "ASI06",
        "name": kind,
        "shortDesc": f"Agentic Sequence Violation: {kind}",
        "level": "error",
    })
    rule_id = f"{info['id']}/{kind}"
    detail = finding.get("detail", "Sequence policy violation")
    evidence = finding.get("evidence", "")

    return {
        "ruleId": rule_id,
        "level": LEVEL_MAP.get(info["level"], "error"),
        "message": {
            "text": f"{info['shortDesc']}: {detail} (Evidence: {evidence})",
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
            "findingType": "dynamic_tool_trace",
            "kind": kind,
            "steps": finding.get("steps", []),
            "evidence": evidence,
        },
    }


def export_sarif(
    score: OWASPScore,
    target_url: str,
    output_path: str | Path = "agentic-redteam.sarif",
    trace_findings: list[dict[str, Any]] | None = None,
) -> Path:
    """
    Export SARIF v2.1.0 report from an OWASPScore and optional dynamic tool trace findings.

    Args:
        score: Computed OWASPScore from compute_owasp_score()
        target_url: The scanned endpoint URL (used as artifact URI in SARIF)
        output_path: Destination file path for the .sarif file
        trace_findings: Optional list of dynamic tool trace findings from tool_harness

    Returns:
        Resolved Path to the written SARIF file.
    """
    results = []
    for cat_score in score.breakdown.values():
        result = _category_to_result(cat_score, target_url)
        if result:
            results.append(result)

    if trace_findings:
        for tf in trace_findings:
            results.append(_trace_finding_to_result(tf, target_url))

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
                            "dynamicTraceFindings": len(trace_findings or []),
                        },
                    }
                ],
            }
        ],
    }

    out = Path(output_path)
    out.write_text(json.dumps(sarif_doc, indent=2))
    return out

