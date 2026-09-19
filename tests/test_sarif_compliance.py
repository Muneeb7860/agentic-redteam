"""Compliance-framework mapping in SARIF output (Round 4 / POSITIONING §3).

Enterprise buyers ask for NIST AI RMF and EU AI Act mapping by name. The SARIF
exporter attaches both to every rule and every result. These tests pin three
things so the mapping cannot silently rot:

  1. Every OWASP/ASI id referenced by the rule tables has a compliance entry —
     so adding a category without mapping it is a loud failure, not a silent
     "unmapped".
  2. A generated SARIF document actually carries the fields on rules and on
     results, and the tags array is present for GitHub Code Scanning.
  3. The lookup never raises on an unknown id (fails safe to "unmapped").
"""
import json

from agentic_redteam.sarif_exporter import (
    COMPLIANCE_MAP,
    OWASP_RULES,
    TRACE_RULES,
    compliance_for,
    export_sarif,
)
from agentic_redteam.scoring import compute_owasp_score


def test_every_rule_id_has_a_compliance_mapping():
    """No category or trace rule may reference an OWASP/ASI id we haven't mapped."""
    used_ids = {info["id"] for info in OWASP_RULES.values()}
    used_ids |= {info["id"] for info in TRACE_RULES.values()}
    missing = sorted(i for i in used_ids if i not in COMPLIANCE_MAP)
    assert not missing, (
        f"rule ids used in SARIF output but absent from COMPLIANCE_MAP: {missing} "
        f"-- add a NIST AI RMF / EU AI Act mapping for each."
    )


def test_compliance_for_never_raises_on_unknown_id():
    got = compliance_for("NOT_A_REAL_ID")
    assert got["nist_ai_rmf"] == "unmapped"
    assert got["eu_ai_act"] == "unmapped"


def test_every_mapping_names_both_frameworks():
    for oid, refs in COMPLIANCE_MAP.items():
        assert refs.get("nist_ai_rmf"), f"{oid} missing NIST AI RMF reference"
        assert refs.get("eu_ai_act"), f"{oid} missing EU AI Act reference"


def test_generated_sarif_carries_compliance_on_rules_and_results(tmp_path):
    # A summary with one failing critical category so at least one result emits.
    summary = {"prompt_injection": {"passed": 0, "failed": 5, "total": 5}}
    score = compute_owasp_score(summary)
    out = export_sarif(score, "https://target.example/api", tmp_path / "out.sarif")
    doc = json.loads(out.read_text())

    driver = doc["runs"][0]["tool"]["driver"]
    rules = driver["rules"]
    assert rules, "no rules emitted"
    for rule in rules:
        props = rule["properties"]
        assert "nistAiRmf" in props and props["nistAiRmf"]
        assert "euAiAct" in props and props["euAiAct"]
        assert "nist-ai-rmf" in props["tags"]
        assert "eu-ai-act" in props["tags"]

    results = doc["runs"][0]["results"]
    assert results, "expected at least one failing-category result"
    for res in results:
        props = res["properties"]
        assert "nistAiRmf" in props and props["nistAiRmf"]
        assert "euAiAct" in props and props["euAiAct"]
