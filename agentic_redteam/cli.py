"""Target-agnostic command line interface for agentic-redteam."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

PACKAGE_DIR = Path(__file__).resolve().parent
PAYLOADS_DIR = PACKAGE_DIR / "payloads"

CATEGORIES = [
    "pii_leakage",
    "prompt_injection",
    "indirect_injection",
    "jailbreak",
    "code_safety",
    "schema_compliance",
    "action_level",
    "clean_queries",
]

CRITICAL = {"prompt_injection", "indirect_injection", "pii_leakage", "jailbreak", "action_level"}


def call_target(url: str, query: str, timeout: float = 60.0) -> dict:
    """Send payload query to the target HTTP endpoint."""
    data = json.dumps({"query": query}).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"status": "http_error", "code": e.code}
    except Exception as e:
        return {"status": "transport_error", "error": str(e)}


def eval_assertion(output_obj: dict, js_body: str) -> bool | None:
    """Safely evaluate output assertion expression without using dangerous eval()."""
    if not isinstance(output_obj, dict) or not js_body:
        return False

    expr = js_body.strip()
    status = str(output_obj.get("status", "")).strip().lower()
    msg = str(output_obj.get("message", "")).lower()
    risk = output_obj.get("risk", {})
    elevated = risk.get("elevated") if isinstance(risk, dict) else False

    # Blocked inequality checks
    if 'status !== "blocked"' in expr or "status != 'blocked'" in expr or 'status != "blocked"' in expr:
        return status != "blocked"
    if 'status === "blocked"' in expr or "status == 'blocked'" in expr or 'status == "blocked"' in expr:
        return status == "blocked"

    # Success inequality checks
    if 'status !== "success"' in expr or "status != 'success'" in expr or 'status != "success"' in expr:
        return status != "success"
    if 'status === "success"' in expr or "status == 'success'" in expr or 'status == "success"' in expr:
        return status == "success"

    # Risk level checks
    if 'risk.elevated === true' in expr or 'risk.elevated == true' in expr:
        return elevated is True
    if 'risk.elevated === false' in expr or 'risk.elevated == false' in expr:
        return elevated is False

    # Fallbacks for simpler keywords
    if "blocked" in expr.lower():
        return status == "blocked" or "blocked" in msg or output_obj.get("blocked") is True
    if "success" in expr.lower():
        return status == "success" or output_obj.get("success") is True

    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Target-agnostic AI agent security red-teaming harness"
    )
    parser.add_argument(
        "categories",
        nargs="*",
        help=f"Payload categories to run (choices: {', '.join(CATEGORIES)})",
    )
    parser.add_argument(
        "--target-url",
        default=os.environ.get("GOVERNANCE_URL", "http://localhost:8000/api/v1/govern"),
        help="Target HTTP endpoint URL",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="Number of evaluation iterations per payload for statistical pass probability",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="CI mode: exit non-zero if any critical category fails",
    )
    parser.add_argument(
        "--output-file",
        "--output",
        dest="output_file",
        default="redteam_results.json",
        help="Output JSON file path for test results",
    )
    parser.add_argument("--adapter", help="Adapter type (ignored for compatibility)")
    parser.add_argument("--model", help="Target model name (ignored for compatibility)")
    parser.add_argument("--timeout", type=float, help="Request timeout (seconds)")
    parser.add_argument("--fail-on", help="Failure condition (ignored for compatibility)")

    args = parser.parse_args()
    
    # Handle categories list which may contain comma-separated values from CLI/Action inputs
    categories_input = []
    if args.categories:
        for cat in args.categories:
            if "," in cat:
                categories_input.extend([x.strip() for x in cat.split(",") if x.strip()])
            else:
                categories_input.append(cat.strip())

    selected_cats = [c for c in CATEGORIES if c in categories_input] if categories_input else CATEGORIES

    iterations = max(1, args.iterations)

    print(f"🛡️  Agentic Red-Team Harness v0.1.0")
    print(f"🎯 Target URL: {args.target_url}")
    print(f"📋 Categories: {', '.join(selected_cats)}")
    print(f"🔄 Statistical Multi-Run Iterations: {iterations}\n")

    summary = {}
    failures = []
    t0 = time.time()

    for cat in selected_cats:
        payload_file = PAYLOADS_DIR / f"{cat}.yaml"
        if not payload_file.exists():
            print(f"⚠️ Payload file for category '{cat}' not found at {payload_file}")
            continue

        tests = yaml.safe_load(payload_file.read_text()) or []
        passed = 0
        failed = 0

        for t in tests:
            desc = t.get("description", "Unnamed test")
            query = t.get("vars", {}).get("query", "")
            
            test_ok = True
            for iter_idx in range(iterations):
                out = call_target(args.target_url, query)

                for a in t.get("assert", []):
                    if a.get("type") == "javascript":
                        res = eval_assertion(out, a.get("value", ""))
                        if res is False:
                            test_ok = False
                            break
                if not test_ok:
                    break

            if test_ok:
                passed += 1
            else:
                failed += 1
                failures.append(
                    {
                        "category": cat,
                        "description": desc,
                        "query": query,
                        "response": out,
                        "iterations": iterations,
                    }
                )

        total = passed + failed
        flag = "✅ PASS" if failed == 0 else "❌ FAIL"
        summary[cat] = {"passed": passed, "failed": failed, "total": total, "pass_rate": round((passed / total) * 100, 1) if total > 0 else 0}
        print(f"[{flag}] {cat:<20} {passed}/{total} passed ({summary[cat]['pass_rate']}%)")

    elapsed = round(time.time() - t0, 2)
    print(f"\n⏱️ Finished in {elapsed}s")

    # Save findings report
    report_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target_url": args.target_url,
        "elapsed_seconds": elapsed,
        "summary": summary,
        "failures": failures,
    }
    Path(args.output_file).write_text(json.dumps(report_data, indent=2))
    print(f"📊 Report saved to {args.output_file}")

    if args.ci:
        crit_failures = [
            f for f in failures if f["category"] in CRITICAL
        ]
        if crit_failures:
            print(f"\n🚨 CI FAIL: {len(crit_failures)} critical red-team test(s) failed!")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
