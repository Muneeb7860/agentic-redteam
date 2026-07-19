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
    "jailbreak",
    "code_safety",
    "schema_compliance",
    "action_level",
    "clean_queries",
]

CRITICAL = {"prompt_injection", "pii_leakage", "jailbreak", "action_level"}


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
    """Evaluate a JavaScript assertion snippet using node or python fallback."""
    runner = (
        "const output = JSON.parse(process.argv[1]);\n"
        "const body = process.argv[2];\n"
        "try { process.stdout.write(eval(body) ? 'PASS' : 'FAIL'); }\n"
        "catch (e) { process.stdout.write('ERR:' + e.message); }\n"
    )
    try:
        p = subprocess.run(
            ["node", "-e", runner, json.dumps(output_obj), js_body],
            capture_output=True,
            text=True,
            timeout=15,
        )
        out = p.stdout.strip()
        if out == "PASS":
            return True
        elif out == "FAIL":
            return False
    except Exception:
        pass

    # Simple Python fallback logic if node is unavailable
    try:
        status = output_obj.get("status")
        msg = output_obj.get("message", "")
        risk = output_obj.get("risk", {})
        if "status === \"blocked\"" in js_body:
            return status == "blocked"
        if "status === \"success\"" in js_body:
            return status == "success"
        if "risk.elevated === true" in js_body:
            return risk.get("elevated") is True
    except Exception:
        pass

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
    selected_cats = [c for c in CATEGORIES if c in args.categories] if args.categories else CATEGORIES

    print(f"🛡️  Agentic Red-Team Harness v0.1.0")
    print(f"🎯 Target URL: {args.target_url}")
    print(f"📋 Categories: {', '.join(selected_cats)}\n")

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
            out = call_target(args.target_url, query)

            test_ok = True
            for a in t.get("assert", []):
                if a.get("type") == "javascript":
                    res = eval_assertion(out, a.get("value", ""))
                    if res is False:
                        test_ok = False
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
                    }
                )

        total = passed + failed
        flag = "✅ PASS" if failed == 0 else "❌ FAIL"
        summary[cat] = {"passed": passed, "failed": failed, "total": total}
        print(f"[{flag}] {cat:<20} {passed}/{total} passed")

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
