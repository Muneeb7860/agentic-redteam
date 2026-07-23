"""Tests for OWASP LLM scoring engine and SARIF exporter in agentic-redteam v1.0.0."""

import json
import tempfile
import unittest
from pathlib import Path
from agentic_redteam.scoring import compute_owasp_score
from agentic_redteam.sarif_exporter import export_sarif, SARIF_SCHEMA


class TestOWASPScoringAndSARIF(unittest.TestCase):

    def test_perfect_score_zero_findings(self):
        summary = {
            "prompt_injection": {"passed": 5, "failed": 0, "total": 5},
            "pii_leakage": {"passed": 3, "failed": 0, "total": 3},
        }
        score = compute_owasp_score(summary)
        self.assertEqual(score.composite, 100)
        self.assertEqual(score.grade, "A")
        self.assertEqual(score.total_passed, 8)
        self.assertEqual(score.total_failed, 0)

    def test_critical_finding_penalty(self):
        summary = {
            "prompt_injection": {"passed": 4, "failed": 2, "total": 6},  # 2 * 4 = 8 penalty
            "code_safety": {"passed": 5, "failed": 1, "total": 6},       # 1 * 3 = 3 penalty
        }
        score = compute_owasp_score(summary)
        self.assertEqual(score.composite, 89)  # 100 - 11
        self.assertEqual(score.grade, "B")
        self.assertEqual(score.total_failed, 3)

    def test_sarif_export_valid_schema(self):
        summary = {
            "prompt_injection": {"passed": 4, "failed": 1, "total": 5},
        }
        score = compute_owasp_score(summary)
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "test.sarif"
            result_path = export_sarif(score, "http://localhost:3000/api/support", out_file)

            self.assertTrue(result_path.exists())
            doc = json.loads(result_path.read_text())

            self.assertEqual(doc["$schema"], SARIF_SCHEMA)
            self.assertEqual(doc["version"], "2.1.0")
            self.assertEqual(len(doc["runs"]), 1)
            run = doc["runs"][0]
            self.assertEqual(run["tool"]["driver"]["name"], "agentic-redteam")
            self.assertEqual(run["tool"]["driver"]["version"], "1.0.0")
            self.assertEqual(len(run["results"]), 1)
            self.assertEqual(run["results"][0]["ruleId"], "LLM01/prompt_injection")
            self.assertEqual(run["results"][0]["level"], "error")


if __name__ == "__main__":
    unittest.main()
