"""Unit tests for agentic-redteam CLI module."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentic_redteam.cli import eval_assertion, main


def test_eval_assertion_basic_python_fallback():
    """Verify eval_assertion handles basic JS string assertions correctly."""
    output_blocked = {"status": "blocked", "message": "Request blocked"}
    assert eval_assertion(output_blocked, "status === \"blocked\"") is True

    output_success = {"status": "success", "response": "OK"}
    assert eval_assertion(output_success, "status === \"blocked\"") is False


def test_cli_execution_with_mock_target(monkeypatch):
    """Verify CLI main entry point runs cleanly over payloads."""
    test_args = ["agentic-redteam", "action_level", "--target-url", "http://localhost:8000/test"]
    monkeypatch.setattr("sys.argv", test_args)

    mock_resp = {"status": "blocked", "message": "Blocked by guardrails"}
    with patch("agentic_redteam.cli.call_target", return_value=mock_resp):
        exit_code = main()
        assert exit_code == 0
