"""
agentic_redteam.benchmark_runner — Empirical AI Security Benchmark & Multi-Target Evaluator

Empirically measures Attack Success Rate (ASR) on adversary payloads,
False Positive Rate (FPR) on clean queries, latency percentiles, and throughput.
Supports single-target and multi-target comparative benchmarking.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable, Dict, List, Optional

import yaml

from agentic_redteam.cli import (
    CATEGORIES,
    PAYLOADS_DIR,
    call_target,
    eval_assertion,
)
from agentic_redteam.scoring import OWASPScore, compute_owasp_score


class BenchmarkRunner:
    """
    Automated benchmark runner for empirical AI agent security evaluation.
    Measures live defense metrics against actual targets without synthetic claims.
    """

    def __init__(
        self,
        target_url: str = "http://localhost:8000/api/v1/govern",
        categories: Optional[List[str]] = None,
        iterations: int = 1,
        body_template: Optional[str] = None,
        custom_caller: Optional[Callable[..., dict]] = None,
    ):
        self.target_url = target_url
        self.categories = categories or [c for c in CATEGORIES if c != "crypto_probes"]
        self.iterations = iterations
        self.body_template = body_template
        self.custom_caller = custom_caller

    def _call(self, query: str) -> dict:
        if self.custom_caller:
            return self.custom_caller(self.target_url, query)
        return call_target(
            url=self.target_url,
            query=query,
            body_template=self.body_template,
        )

    def run(self) -> Dict[str, Any]:
        """
        Execute an empirical benchmark run against the configured target.
        """
        t0 = time.time()
        latencies: List[float] = []
        summary: Dict[str, Dict[str, int]] = {}

        for cat in self.categories:
            payload_path = PAYLOADS_DIR / f"{cat}.yaml"
            if not payload_path.exists():
                continue

            with open(payload_path, "r", encoding="utf-8") as f:
                payloads = yaml.safe_load(f) or []

            cat_passed = 0
            cat_failed = 0

            for p in payloads:
                query = p.get("vars", {}).get("query", "")
                assertions = p.get("assert", [])

                for _ in range(self.iterations):
                    call_t0 = time.time()
                    resp = self._call(query)
                    latencies.append(time.time() - call_t0)

                    test_ok = True
                    for a in assertions:
                        val = a.get("value", "")
                        if eval_assertion(resp, val) is False:
                            test_ok = False
                            break

                    if test_ok:
                        cat_passed += 1
                    else:
                        cat_failed += 1

            summary[cat] = {
                "passed": cat_passed,
                "failed": cat_failed,
                "total": cat_passed + cat_failed,
            }

        elapsed_sec = max(time.time() - t0, 0.001)
        owasp_score: OWASPScore = compute_owasp_score(summary)
        total_tests = owasp_score.total_tests

        # Attack success rate, and the TARGET's over-refusal rate.
        #
        # Deliberately NOT called "false positive rate". In security tooling
        # that phrase means the SCANNER's false positives, so a report reading
        # false_positive_rate_pct: 100.0 says "this scanner is wrong every
        # time" -- the precise opposite of what is being measured, and the
        # opposite of this package's strongest verified property (0/10 false
        # positives against a live agent). It measures how many BENIGN queries
        # the target declined, which the CLI already reports as over-refusal.
        # One name for one concept.
        clean_stats = summary.get("clean_queries", {})
        clean_total = clean_stats.get("total", 0)
        clean_passed = clean_stats.get("passed", 0)
        over_refusal = round(((clean_total - clean_passed) / clean_total) * 100, 2) if clean_total > 0 else 0.0

        adv_failed = sum(s["failed"] for c, s in summary.items() if c != "clean_queries")
        adv_total = sum(s["total"] for c, s in summary.items() if c != "clean_queries")
        asr = round((adv_failed / adv_total) * 100, 2) if adv_total > 0 else 0.0

        # Latency statistics
        latencies_ms = [round(l * 1000, 2) for l in latencies]
        latencies_sorted = sorted(latencies_ms) if latencies_ms else [0.0]
        p50 = latencies_sorted[len(latencies_sorted) // 2]
        p95 = latencies_sorted[int(len(latencies_sorted) * 0.95)] if len(latencies_sorted) >= 20 else latencies_sorted[-1]

        return {
            "target_url": self.target_url,
            "overall_pass_rate": owasp_score.overall_pass_rate,
            "owasp_composite_score": owasp_score.composite,
            "owasp_grade": owasp_score.grade,
            "total_tests": total_tests,
            "total_passed": owasp_score.total_passed,
            "total_failed": owasp_score.total_failed,
            "attack_success_rate_pct": asr,
            "target_over_refusal_rate_pct": over_refusal,
            "latency": {
                "total_seconds": round(elapsed_sec, 3),
                "p50_ms": p50,
                "p95_ms": p95,
                "avg_ms": round(sum(latencies_ms) / len(latencies_ms), 2) if latencies_ms else 0.0,
            },
            "throughput_req_per_sec": round(total_tests / elapsed_sec, 2),
            "summary": summary,
        }

    @classmethod
    def run_multi_target_comparison(
        cls,
        targets: Dict[str, str],
        categories: Optional[List[str]] = None,
        iterations: int = 1,
    ) -> Dict[str, Any]:
        """
        Run a comparative benchmark sweep across multiple named targets side-by-side.
        """
        results: Dict[str, Any] = {}
        for name, url in targets.items():
            runner = cls(target_url=url, categories=categories, iterations=iterations)
            results[name] = runner.run()
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "targets_evaluated": len(targets),
            "results": results,
        }


def run_automated_benchmark(
    target_url: str = "http://localhost:8000/api/v1/govern",
    categories: Optional[List[str]] = None,
    iterations: int = 1,
) -> Dict[str, Any]:
    """Convenience function to run the benchmark suite."""
    runner = BenchmarkRunner(target_url=target_url, categories=categories, iterations=iterations)
    return runner.run()
