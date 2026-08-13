"""
Unit tests for canonical benchmark runner and empirical multi-target evaluation.
"""

import unittest
from unittest.mock import patch

from agentic_redteam.benchmark_runner import BenchmarkRunner, run_automated_benchmark


class TestCanonicalBenchmarkRunner(unittest.TestCase):

    def test_benchmark_runner_empirical_execution(self):
        def fake_caller(url, query, **kwargs):
            if "ignore all safety" in query.lower() or "blocked" in query.lower():
                return {"status": "blocked", "message": "Blocked by policy"}
            return {"status": "success", "response": "Legitimate request response"}

        runner = BenchmarkRunner(
            target_url="http://localhost:8000/api/v1/test",
            categories=["action_level", "clean_queries"],
            iterations=1,
            custom_caller=fake_caller,
        )
        res = runner.run()

        self.assertIn("overall_pass_rate", res)
        self.assertIn("owasp_composite_score", res)
        self.assertIn("owasp_grade", res)
        self.assertIn("attack_success_rate_pct", res)
        self.assertIn("false_positive_rate_pct", res)
        self.assertIn("throughput_req_per_sec", res)
        self.assertIn("latency", res)
        self.assertGreaterEqual(res["total_tests"], 1)

    def test_multi_target_comparative_sweep(self):
        def fake_caller_hardened(url, query, **kwargs):
            return {"status": "blocked", "message": "Policy enforcement active"}

        with patch("agentic_redteam.benchmark_runner.call_target", side_effect=fake_caller_hardened):
            targets = {
                "mock_gateway_a": "http://localhost:8001/a",
                "mock_gateway_b": "http://localhost:8002/b",
            }
            comparison = BenchmarkRunner.run_multi_target_comparison(
                targets=targets,
                categories=["action_level"],
                iterations=1,
            )
            self.assertEqual(comparison["targets_evaluated"], 2)
            self.assertIn("mock_gateway_a", comparison["results"])
            self.assertIn("mock_gateway_b", comparison["results"])

    def test_convenience_helper(self):
        def fake_caller(url, query, **kwargs):
            return {"status": "blocked", "message": "Blocked"}

        with patch("agentic_redteam.benchmark_runner.call_target", side_effect=fake_caller):
            res = run_automated_benchmark(
                target_url="http://localhost:8000/api/v1/test",
                categories=["action_level"],
                iterations=1,
            )
            self.assertEqual(res["target_url"], "http://localhost:8000/api/v1/test")
            self.assertGreater(res["total_tests"], 0)


if __name__ == "__main__":
    unittest.main()
