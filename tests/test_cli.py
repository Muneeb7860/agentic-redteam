"""Unit tests for agentic-redteam CLI module."""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentic_redteam.cli import call_target, eval_assertion, main
from agentic_redteam.crypto import sign_payload, verify_payload_signature


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


class TestEvalAssertionCompound(unittest.TestCase):
    """Regression tests for the eval_assertion() `||`/`&&` bug: a naive
    any()/all() over a list of per-disjunct results silently drops any
    disjunct that doesn't match an enumerated literal string form, which
    collapses "unresolved" into "False" whenever the remaining resolved
    disjuncts happen to be False. This broke multi_turn.yaml's turn-1
    tautology sanity check (`status !== 'blocked' || status === 'blocked'`,
    which must always be True regardless of status) -- the first disjunct
    (triple-equals + single-quotes) matched no enumerated literal form and
    was silently dropped, and any([False]) from the second disjunct alone
    returned False for an expression that's true by construction."""

    OR_EXPR = (
        'r.status === "blocked" || (r.risk && r.risk.elevated === true)'
    )

    @staticmethod
    def harness_pass(result):
        """Mirror the CLI's own pass/fail decision (cli.py: `if res is False:
        test_ok = False`) — both True AND None ("can't fully resolve this
        sub-clause") count as passing. The `r.risk &&` half of an AND clause
        is a bare existence-guard the atomic matcher can't independently
        verify (no generic truthiness evaluator), so a clause like
        `r.risk && r.risk.elevated === true` legitimately resolves to None
        rather than True — that's honest "unresolved", not a bug."""
        return result is not False

    def test_or_true_via_first_branch_blocked(self):
        out = {"status": "blocked"}
        self.assertTrue(eval_assertion(out, self.OR_EXPR))

    def test_or_true_via_second_branch_risk_elevated(self):
        """The regression case: status is 'success' (not blocked), but
        risk.elevated is True — the || fallback must be reached (and must
        not fail the assertion)."""
        out = {"status": "success", "risk": {"elevated": True, "signals": ["x"]}}
        self.assertTrue(self.harness_pass(eval_assertion(out, self.OR_EXPR)))

    def test_or_false_when_neither_branch_satisfied(self):
        out = {"status": "success", "risk": {"elevated": False, "signals": []}}
        self.assertFalse(eval_assertion(out, self.OR_EXPR))

    def test_or_false_when_risk_missing_entirely(self):
        out = {"status": "success"}
        self.assertFalse(eval_assertion(out, self.OR_EXPR))

    def test_simple_or_both_success_and_blocked_are_valid(self):
        expr = 'r.status === "blocked" || r.status === "success"'
        self.assertTrue(eval_assertion({"status": "success"}, expr))
        self.assertTrue(eval_assertion({"status": "blocked"}, expr))
        self.assertFalse(eval_assertion({"status": "http_error"}, expr))

    def test_three_way_or_with_warnings_clause(self):
        expr = 'r.status === "blocked" || (r.warnings && r.warnings.length > 0) || r.status === "success"'
        self.assertTrue(eval_assertion({"status": "success"}, expr))
        self.assertTrue(eval_assertion({"status": "blocked"}, expr))

    def test_and_all_true(self):
        expr = 'r.status === "success" && r.risk.elevated === false'
        out = {"status": "success", "risk": {"elevated": False}}
        self.assertTrue(eval_assertion(out, expr))

    def test_and_short_circuits_false(self):
        expr = 'r.status === "success" && r.risk.elevated === true'
        out = {"status": "blocked", "risk": {"elevated": True}}
        self.assertFalse(eval_assertion(out, expr))

    def test_negation_single_quotes_triple_equals(self):
        """Regression: `status !== 'blocked'` (triple-equals + single-quotes
        — exactly what multi_turn.yaml uses) matched none of the previously
        enumerated literal forms and fell through to a negation-blind
        substring fallback, silently flipping the result."""
        self.assertTrue(eval_assertion({"status": "success"}, "status !== 'blocked'"))
        self.assertFalse(eval_assertion({"status": "blocked"}, "status !== 'blocked'"))

    def test_status_error_comparisons_are_genuinely_evaluated(self):
        self.assertTrue(eval_assertion({"status": "success"}, 'r.status !== "error"'))
        self.assertFalse(eval_assertion({"status": "error"}, 'r.status !== "error"'))

    def test_simple_non_compound_assertions_are_unaffected(self):
        self.assertTrue(eval_assertion({"status": "blocked"}, 'status === "blocked"'))
        self.assertFalse(eval_assertion({"status": "success"}, 'status === "blocked"'))
        self.assertTrue(
            eval_assertion({"status": "success", "risk": {"elevated": True}}, "risk.elevated === true")
        )

    def test_nested_parens_do_not_break_splitting(self):
        expr = '(r.status === "blocked") || (r.risk && r.risk.elevated === true)'
        out = {"status": "success", "risk": {"elevated": True}}
        self.assertTrue(self.harness_pass(eval_assertion(out, expr)))

    def test_tautology_is_always_true_regardless_of_status(self):
        """The exact multi_turn.yaml turn-1 regression case: a deliberate
        always-true sanity check must evaluate True no matter what status
        is, not just for the branch that happens to match a literal form."""
        expr = "status !== 'blocked' || status === 'blocked'"
        self.assertTrue(eval_assertion({"status": "success"}, expr))
        self.assertTrue(eval_assertion({"status": "blocked"}, expr))

    def test_pending_approval_is_treated_as_blocked(self):
        """HITL-aware categories (action_level, mcp_security) assert
        pending_approval the same way as blocked — a human/step-up gate
        catching the request is a pass, not a silent miss."""
        out = {"status": "pending_approval", "requires_hitl": True}
        self.assertTrue(eval_assertion(out, 'status === "blocked"'))


class TestCallTargetSigning(unittest.TestCase):
    """ASI07: call_target() must sign every outgoing request with
    SWISH_AGENT_SHARED_SECRET when it's configured (so mandatory server-side
    enforcement doesn't lock the harness's own categories out), and must
    stay backward compatible (no signature headers) when it isn't."""

    def _mock_urlopen(self, captured_requests):
        def _fake_urlopen(req, timeout=None):
            captured_requests.append(req)
            body = json.dumps({"status": "success"}).encode()
            resp = MagicMock()
            # call_target reads via http_utils.read_capped(), which loops
            # calling resp.read(chunk_size) until it gets b"" (EOF) — a
            # fixed `.return_value` ignores the size arg and never returns
            # b"", so the loop never terminates on a real socket-like
            # object. Emulate a real one-shot-then-EOF stream instead.
            remaining = [body]
            def _read(size=-1):
                if not remaining:
                    return b""
                chunk = remaining.pop(0)
                return chunk
            resp.read.side_effect = _read
            resp.__enter__.return_value = resp
            resp.__exit__.return_value = False
            return resp

        return _fake_urlopen

    def test_no_secret_configured_sends_no_signature_headers(self):
        captured = []
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SWISH_AGENT_SHARED_SECRET", None)
            with patch("urllib.request.urlopen", new=self._mock_urlopen(captured)):
                call_target("http://localhost:8000/api/v1/govern", "hello")

        self.assertEqual(len(captured), 1)
        self.assertNotIn("X-Agent-Signature", captured[0].headers)

    def test_secret_configured_signs_request_and_server_side_verification_succeeds(self):
        """Round-trip through the real server-side verifier
        (crypto.verify_payload_signature) using the exact payload dict
        call_target actually serializes, proving the signed request would
        be accepted by a mandatory-enforcement server."""
        captured = []
        secret = "shared-test-secret"
        with patch.dict(os.environ, {"SWISH_AGENT_SHARED_SECRET": secret, "SWISH_AGENT_ID": "harness-test"}):
            with patch("urllib.request.urlopen", new=self._mock_urlopen(captured)):
                call_target("http://localhost:8000/api/v1/govern", "probe query", session_id="sess-1")

        self.assertEqual(len(captured), 1)
        req = captured[0]
        self.assertEqual(req.headers.get("X-agent-id"), "harness-test")
        self.assertIsNotNone(req.headers.get("X-agent-signature"))

        sent_payload = json.loads(req.data.decode("utf-8"))
        ok, msg = verify_payload_signature(dict(req.header_items()), secret, sent_payload)
        self.assertTrue(ok, msg)

    def test_secret_configured_wrong_key_is_rejected(self):
        captured = []
        with patch.dict(os.environ, {"SWISH_AGENT_SHARED_SECRET": "correct-secret"}):
            with patch("urllib.request.urlopen", new=self._mock_urlopen(captured)):
                call_target("http://localhost:8000/api/v1/govern", "probe query")

        req = captured[0]
        sent_payload = json.loads(req.data.decode("utf-8"))
        ok, _ = verify_payload_signature(dict(req.header_items()), "wrong-secret", sent_payload)
        self.assertFalse(ok)


# ── empty-selection fail-open, found by an end-to-end run ───────────────

def _run_cli(args):
    """Invoke the CLI entrypoint, returning its exit code."""
    import agentic_redteam.cli as cli
    import sys
    argv = sys.argv
    try:
        sys.argv = ["agentic-redteam"] + args
        return cli.main()
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1
    finally:
        sys.argv = argv


def test_unknown_category_does_not_score_a_on_zero_tests():
    """Regression for a real fail-open. A name matching nothing was filtered
    out silently and the run scored 0/0 = 100% -> Grade A, exit 0. One typo in
    a CI config ('jailbreek') produced a green build that tested nothing.

    Vacuous truth is not a pass, here as everywhere else in this package."""
    assert _run_cli(["jailbreek", "--target-url", "http://127.0.0.1:9"]) == 2


def test_partial_match_refuses_rather_than_silently_narrowing():
    """One valid name and one typo used to scan only the valid one and report
    success -- a result covering a fraction of what was asked for, presented as
    if it covered all of it."""
    assert _run_cli(["ssrf", "jailbreek", "--target-url", "http://127.0.0.1:9"]) == 2


def test_valid_categories_are_not_rejected():
    """The guard must not fire on correct input."""
    rc = _run_cli(["clean_queries", "--target-url", "http://127.0.0.1:9"])
    assert rc != 2, "valid category must not be treated as unknown"
