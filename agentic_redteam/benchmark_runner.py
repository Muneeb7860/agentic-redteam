"""
SwishOS agentic-redteam v0.5.0 Automated Benchmark Runner
Programmatic execution module that sweeps target endpoints across all payload categories,
cryptographic identity probes, and fingerprint tarpit tests, exporting dual Markdown/JSON reports.
"""

from __future__ import annotations
import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, List

from agentic_redteam.crypto_probes import run_crypto_probes
from agentic_redteam.fingerprint_test import run_fingerprint_tarpit_exhaustion
from agentic_redteam.sdk import RedTeamSDK

def run_automated_benchmark(
    target_url: str,
    categories: List[str] | None = None,
    output_dir: str = "."
) -> Dict[str, Any]:
    """
    Executes a full automated security benchmark sweep against target_url.
    Generates dual BENCHMARK_REPORT.md and benchmark_results.json files.
    """
    t0 = time.time()
    sdk = RedTeamSDK(target_url=target_url)

    all_categories = categories or [
        "action_level",
        "centroid_probes",
        "clean_queries",
        "code_safety",
        "indirect_injection",
        "jailbreak",
        "multi_turn",
        "pii_leakage",
        "prompt_injection",
        "schema_compliance",
    ]

    category_results = {}
    total_passed = 0
    total_probes = 0

    for cat in all_categories:
        try:
            res = sdk.run_category(cat)
            passed = res.get("passed", 0)
            total = res.get("total", 0)
            total_passed += passed
            total_probes += total
            category_results[cat] = {
                "passed": passed,
                "total": total,
                "pass_rate": round((passed / total * 100) if total > 0 else 0, 1),
            }
        except Exception as e:
            category_results[cat] = {"passed": 0, "total": 0, "pass_rate": 0.0, "error": str(e)}

    # Cryptographic Identity Probes
    crypto_res = run_crypto_probes(target_url)
    crypto_passed = sum(1 for p in crypto_res if p.get("passed"))
    crypto_total = len(crypto_res)

    # Subnet Tarpit Stress-Test
    tarpit_res = run_fingerprint_tarpit_exhaustion(target_url)

    elapsed = round(time.time() - t0, 2)
    overall_pass_rate = round((total_passed / total_probes * 100) if total_probes > 0 else 0, 1)

    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target_url": target_url,
        "execution_time_seconds": elapsed,
        "overall_pass_rate": overall_pass_rate,
        "total_probes": total_probes,
        "total_passed": total_passed,
        "category_breakdown": category_results,
        "crypto_probes": {
            "passed": crypto_passed,
            "total": crypto_total,
            "details": crypto_res,
        },
        "tarpit_test": tarpit_res,
    }

    # 1. Export JSON Data
    json_path = Path(output_dir) / "benchmark_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # 2. Export Markdown Report
    md_path = Path(output_dir) / "BENCHMARK_REPORT.md"
    _generate_markdown_report(summary, md_path)

    return summary

def _generate_markdown_report(summary: Dict[str, Any], file_path: Path) -> None:
    lines = [
        "# 🛡️ SwishOS `agentic-redteam` v0.5.0 Benchmark Report",
        "",
        f"**Target URL:** `{summary['target_url']}`  ",
        f"**Timestamp:** `{summary['timestamp']}`  ",
        f"**Execution Duration:** `{summary['execution_time_seconds']} seconds`  ",
        f"**Overall Defense Pass Rate:** `{summary['overall_pass_rate']}%` ({summary['total_passed']}/{summary['total_probes']})  ",
        "",
        "## 📊 Payload Category Breakdown",
        "",
        "| Category | Passed / Total | Pass Rate |",
        "| :--- | :---: | :---: |",
    ]

    for cat, data in summary["category_breakdown"].items():
        lines.append(f"| `{cat}` | {data['passed']}/{data['total']} | **{data['pass_rate']}%** |")

    lines.extend([
        "",
        "## 🔑 Cryptographic Identity & Audit Proof Probes",
        "",
        f"**Crypto Probes Pass Rate:** `{summary['crypto_probes']['passed']}/{summary['crypto_probes']['total']}`  ",
        "",
        "## ⏱️ Subnet Fingerprint Tarpit Enforcement",
        "",
        f"**Tarpit Active:** `{summary['tarpit_test'].get('tarpit_active')}`  ",
        f"**Latency Multipliers:** `{summary['tarpit_test'].get('latencies_ms')}`  ",
    ])

    with open(file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def main() -> None:
    parser = argparse.ArgumentParser(description="SwishOS agentic-redteam v0.5.0 Automated Benchmark Runner")
    parser.add_argument("--target", required=True, help="Target URL endpoint")
    parser.add_argument("--output-dir", default=".", help="Directory to save benchmark reports")
    args = parser.parse_args()

    print(f"🚀 Launching Automated Security Benchmark against {args.target}...")
    run_automated_benchmark(args.target, output_dir=args.output_dir)
    print("✅ Benchmark complete! Saved BENCHMARK_REPORT.md and benchmark_results.json.")

if __name__ == "__main__":
    main()
