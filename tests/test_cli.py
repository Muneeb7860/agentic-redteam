"""Unit tests for agentic-redteam CLI module."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentic_redteam.cli import eval_assertion, main


class TestAgenticRedteamCLI(unittest.TestCase):
    def test_eval_assertion_basic_python_fallback(self):
        """Verify eval_assertion handles basic assertions correctly without eval()."""
        output_blocked = {"status": "blocked", "message": "Request blocked"}
        self.assertTrue(eval_assertion(output_blocked, 'status === "blocked"'))

        output_success = {"status": "success", "response": "OK"}
        self.assertFalse(eval_assertion(output_success, 'status === "blocked"'))

    def test_cli_execution_with_mock_target(self):
        """Verify CLI main entry point runs cleanly over payloads."""
        test_args = ["agentic-redteam", "action_level", "--target-url", "http://localhost:8000/test"]
        with patch("sys.argv", test_args):
            mock_resp = {"status": "blocked", "message": "Blocked by guardrails"}
            with patch("agentic_redteam.cli.call_target", return_value=mock_resp):
                exit_code = main()
                self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
