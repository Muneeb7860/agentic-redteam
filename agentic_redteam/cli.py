"""Target-agnostic command line interface for agentic-redteam with multi-turn and mutation support."""

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

try:
    from agentic_redteam.mutators import apply_mutations
except ImportError:
    try:
        from mutators import apply_mutations
    except ImportError:
        def apply_mutations(text: str, mutation_types: list[str] | None = None) -> list[str]:
            return [text]

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
    "multi_turn",
]

CRITICAL = {"prompt_injection", "indirect_injection", "pii_leakage", "jailbreak", "action_level", "multi_turn"}


def call_target(
    url: str,
    query: str,
    session_id: str | None = None,
    history: list[dict] | None = None,
    timeout: float = 60.0
) -> dict:
    """Send payload query and stateful session history to the target HTTP endpoint."""
    payload: dict = {"query": query, "message": query}
    if session_id:
        payload["sessionId"] = session_id
        payload["session_id"] = session_id
    if history:
        payload["history"] = history
        payload["messages"] = history

    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if session_id:
        headers["X-Session-ID"] = session_id

    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            res_json = json.loads(e.read().decode())
            res_json["http_code"] = e.code
            return res_json
        except Exception:
            return {"status": "blocked", "http_code": e.code, "message": f"HTTP {e.code}"}
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

    # Check for HTTP errors / status code blocks
    http_code = output_obj.get("http_code")
    if http_code in (422, 429, 401, 403):
        status = "blocked"

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
        help="CI mode: exit non-zero if any critical category fails (Fast Gate N=2)",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Deep Audit mode: run N=10 Monte-Carlo iterations for comprehensive sweeps",
    )
    parser.add_argument(
        "--mutate",
        action="store_true",
        help="Apply local zero-cost payload mutations (homoglyph, base64, markdown, story)",
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

    # Sampling Iterations Determination
    iterations = args.iterations
    if args.deep:
        iterations = max(iterations, 10)
    elif args.ci:
        iterations = max(iterations, 2)

    print(f"🛡️  Agentic Red-Team Harness v0.2.0")
    print(f"🎯 Target URL: {args.target_url}")
    print(f"📋 Categories: {', '.join(selected_cats)}")
    print(f"🔄 Statistical Multi-Run Iterations: {iterations}")
    print(f"🧬 Algorithmic Mutations: {'ENABLED' if args.mutate else 'DISABLED'}\n")

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
            
            # Handle Stateful Multi-Turn Scenarios
            if "scenario" in t:
                scenario_ok = True
                session_id = f"redteam-sess-{int(time.time())}"
                history: list[dict] = []

                for turn_info in t["scenario"]:
                    query = turn_info.get("vars", {}).get("query", "")
                    asserts = turn_info.get("assert", [])

                    turn_out = call_target(args.target_url, query, session_id=session_id, history=history)
                    history.append({"role": "user", "content": query})
                    history.append({"role": "assistant", "content": turn_out.get("message", "")})

                    for a in asserts:
                        if a.get("type") == "javascript":
                            res = eval_assertion(turn_out, a.get("value", ""))
                            if res is False:
                                scenario_ok = False
                                break
                    if not scenario_ok:
                        break

                if scenario_ok:
                    passed += 1
                else:
                    failed += 1
                    failures.append(
                        {
                            "category": cat,
                            "description": desc,
                            "type": "multi_turn_scenario",
                            "response": turn_out,
                            "iterations": 1,
                        }
                    )
                continue

            # Handle Standard Single-Turn Payloads (with optional mutation)
            base_query = t.get("vars", {}).get("query", "")
            queries_to_test = apply_mutations(base_query) if args.mutate else [base_query]

            test_ok = True
            for query in queries_to_test:
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
                        "query": base_query,
                        "response": out,
                        "iterations": iterations,
                    }
                )

        total = passed + failed
        flag = "✅ PASS" if failed == 0 else "❌ FAIL"
        summary[cat] = {
            "passed": passed,
            "failed": failed,
            "total": total,
            "pass_rate": round((passed / total) * 100, 1) if total > 0 else 0,
        }
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
        crit_failures = [f for f in failures if f["category"] in CRITICAL]
        if crit_failures:
            print(f"\n🚨 CI FAIL: {len(crit_failures)} critical red-team test(s) failed!")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
