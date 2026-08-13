"""
Unit tests validating payload files integrity and category registry in canonical package.
"""

import unittest
from pathlib import Path
import yaml

from agentic_redteam.cli import CATEGORIES, PAYLOADS_DIR
from agentic_redteam.remediation import REMEDIATIONS, get_remediation
from agentic_redteam.scoring import SEVERITY_WEIGHTS


class TestCanonicalPayloadsIntegrity(unittest.TestCase):

    def test_existing_payload_files_are_valid(self):
        yaml_files = list(PAYLOADS_DIR.glob("*.yaml"))
        self.assertGreaterEqual(len(yaml_files), 10)
        for yaml_file in yaml_files:
            content = yaml.safe_load(yaml_file.read_text())
            self.assertIsInstance(
                content, list,
                f"Payload file {yaml_file.name} must be a list of test cases."
            )
            self.assertGreater(
                len(content), 0,
                f"Payload file {yaml_file.name} cannot be empty."
            )

    def test_new_agentic_payloads_structure(self):
        new_cats = ["tool_orchestration_abuse", "autonomous_agent_drift", "cross_context_retrieval"]
        for cat in new_cats:
            yaml_file = PAYLOADS_DIR / f"{cat}.yaml"
            self.assertTrue(yaml_file.exists())
            content = yaml.safe_load(yaml_file.read_text())
            self.assertIsInstance(content, list)
            self.assertGreaterEqual(len(content), 4)

            for item in content:
                self.assertIn("description", item)
                self.assertIn("vars", item)
                self.assertIn("assert", item)

    def test_remediation_coverage_for_all_categories(self):
        for cat in CATEGORIES:
            rem = get_remediation(cat)
            self.assertIsNotNone(rem.control)
            self.assertIsNotNone(rem.root_cause)
            self.assertGreaterEqual(len(rem.fix_steps), 1)

    def test_severity_weights_match_critical_categories(self):
        for cat in CATEGORIES:
            self.assertIn(
                cat, SEVERITY_WEIGHTS,
                f"Category '{cat}' is missing from SEVERITY_WEIGHTS dictionary in scoring.py"
            )


if __name__ == "__main__":
    unittest.main()
