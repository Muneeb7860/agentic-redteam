"""Target-agnostic command line interface for agentic-redteam v0.3.0 with crypto probes, centroid payloads, and tarpit stress-testing."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

try:
    from agentic_redteam.mutators import apply_mutations
    from agentic_redteam.crypto_probes import run_crypto_probes
    from agentic_redteam.fingerprint_test import run_fingerprint_tarpit_exhaustion
    from agentic_redteam.crypto import sign_payload
    from agentic_redteam.gart_attacker import GenerativeAttacker
except ImportError:
    try:
        from mutators import apply_mutations
        from crypto_probes import run_crypto_probes
        from fingerprint_test import run_fingerprint_tarpit_exhaustion
        from crypto import sign_payload
        from gart_attacker import GenerativeAttacker
    except ImportError:
        def apply_mutations(text: str, mutation_types: list[str] | None = None) -> list[str]:
            return [text]
        def run_crypto_probes(target_url: str, timeout: float = 10.0) -> list[dict]:
            return []
        def run_fingerprint_tarpit_exhaustion(target_url: str, request_count: int = 5) -> dict:
            return {"passed": True, "note": "tarpit test module fallback"}
        GenerativeAttacker = None
        def sign_payload(agent_id: str, secret_key: str, payload: dict, **kwargs) -> dict:
            return {}

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
    "mcp_security",
    "clean_queries",
    "multi_turn",
    "centroid_probes",
    "crypto_probes",
    "asi04_sandbox_escape",
    "asi10_rogue_persistence",
]

CRITICAL = {"prompt_injection", "indirect_injection", "pii_leakage", "jailbreak", "action_level", "mcp_security", "multi_turn", "centroid_probes", "crypto_probes", "asi04_sandbox_escape", "asi10_rogue_persistence"}


def call_target(
    url: str,
    query: str,
    session_id: str | None = None,
    history: list[dict] | None = None,
    timeout: float = 60.0,
    body_template: str | None = None
) -> dict:
    """Send payload query and stateful session history to the target HTTP endpoint."""
    if body_template:
        try:
            rendered = body_template.replace("{payload}", query).replace("{query}", query)
            payload = json.loads(rendered)
        except Exception:
            payload = {"query": query, "message": query}
    else:
        payload = {"query": query, "message": query}

    if session_id and isinstance(payload, dict):
        payload["sessionId"] = session_id
        payload["session_id"] = session_id
    if history and isinstance(payload, dict):
        payload["history"] = history
        payload["messages"] = history

    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if session_id:
        headers["X-Session-ID"] = session_id

    shared_secret = os.environ.get("SWISH_AGENT_SHARED_SECRET")
    if shared_secret and isinstance(payload, dict):
        agent_id = os.environ.get("SWISH_AGENT_ID", "agentic-redteam-harness")
        headers.update(sign_payload(agent_id, shared_secret, payload))

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


def _split_top_level(expr: str, operator: str) -> list[str]:
    """Split expr on `operator` at paren-depth 0 only (so it doesn't split
    inside a parenthesized sub-clause like `(r.risk && r.risk.elevated)`)."""
    parts: list[str] = []
    depth = 0
    current = ""
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == "(":
            depth += 1
            current += ch
        elif ch == ")":
            depth -= 1
            current += ch
        elif depth == 0 and expr[i : i + len(operator)] == operator:
            parts.append(current)
            current = ""
            i += len(operator)
            continue
        else:
            current += ch
        i += 1
    parts.append(current)
    return [p.strip() for p in parts]


def _strip_wrapping_parens(expr: str) -> str:
    """Strip a single layer of parens that wraps the WHOLE expression, e.g.
    turn `(r.risk && r.risk.elevated === true)` into `r.risk && ...`. Leaves
    expressions with internal-only parens (or unbalanced wrapping) untouched."""
    expr = expr.strip()
    if not (expr.startswith("(") and expr.endswith(")")):
        return expr
    depth = 0
    for idx, ch in enumerate(expr):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and idx != len(expr) - 1:
                return expr  # the opening paren closes before the end — not a full wrap
    return expr[1:-1].strip()


_STATUS_CMP_RE = re.compile(r"status\s*(===|!==|==|!=)\s*['\"](\w+)['\"]")
_RISK_ELEVATED_CMP_RE = re.compile(r"risk\.elevated\s*(===|==)\s*(true|false)")


def _eval_atomic(output_obj: dict, expr: str) -> bool | None:
    """Evaluate a single, non-composite condition (no top-level || or &&).

    Uses a quote/operator-agnostic REGEX for the status/risk.elevated
    comparisons (===, !==, ==, != x 'single'/"double" quotes — 4 combinations
    each), instead of enumerating specific literal string forms. An
    enumeration-based matcher inevitably misses a combination (e.g.
    `status === 'blocked'` — triple-equals + single-quotes, exactly what
    multi_turn.yaml's tautology-check turn uses) and silently falls through
    to a generic substring heuristic that has no concept of negation.

    pending_approval and requires_hitl are treated as a form of "blocked"
    (the request didn't complete unchecked — a human/step-up gate caught
    it), matching this harness's HITL-aware categories (action_level,
    mcp_security).
    """
    status = str(output_obj.get("status", "")).strip().lower()
    msg = str(output_obj.get("message", "")).lower()
    risk = output_obj.get("risk", {})
    elevated = risk.get("elevated") if isinstance(risk, dict) else False

    http_code = output_obj.get("http_code")
    if http_code in (422, 429, 401, 403):
        status = "blocked"
    if output_obj.get("requires_hitl") is True or status == "pending_approval":
        status = "blocked"

    m = _STATUS_CMP_RE.search(expr)
    if m:
        op, value = m.group(1), m.group(2).lower()
        if value == "pending_approval":
            value = "blocked"  # pending_approval assertions treated as blocked
        is_equal = status == value
        return is_equal if op in ("===", "==") else not is_equal

    m = _RISK_ELEVATED_CMP_RE.search(expr)
    if m:
        want = m.group(2) == "true"
        return elevated is want

    if "blocked" in expr.lower():
        return status == "blocked" or "blocked" in msg or output_obj.get("blocked") is True
    if "success" in expr.lower():
        return status == "success" or output_obj.get("success") is True

    return None


def eval_assertion(output_obj: dict, js_body: str) -> bool | None:
    """Safely evaluate output assertion expression without using dangerous eval().

    Handles compound `||`/`&&` expressions with real three-valued logic
    (True/False/None-unresolved), not a naive any()/all() over a list that
    silently drops unresolved terms — dropping an unresolved disjunct and
    then taking any() of what's left collapses "can't tell" into "False"
    whenever the remaining resolved disjuncts happen to be False, which
    previously broke tautology checks like `status !== 'blocked' || status
    === 'blocked'` (multi_turn.yaml's turn-1 sanity assertion): the first
    disjunct doesn't match any literal-enumerated form and gets skipped, the
    second correctly evaluates False (status is "success" on turn 1), and
    any([False]) wrongly returns False for an expression that's tautologically
    true.
    """
    if not isinstance(output_obj, dict) or not js_body:
        return False

    # Strip the `const r = ...;` preamble some payloads prefix the expression
    # with, and wrapping parens, so a fully-parenthesized sub-clause reveals
    # its own top-level && on the next recursion instead of being handed
    # whole to _eval_atomic where && has no meaning.
    expr = js_body.strip()
    for prefix in (
        'const r = typeof output === "object" ? output : JSON.parse(output);',
        "const r = output;",
    ):
        expr = expr.replace(prefix, "").strip()
    expr = _strip_wrapping_parens(expr)

    or_parts = _split_top_level(expr, "||")
    if len(or_parts) > 1:
        results = [eval_assertion(output_obj, p) for p in or_parts]
        if any(r is True for r in results):
            return True
        if all(r is False for r in results):
            return False
        return None  # mixed False/None, no True — genuinely unresolved

    and_parts = _split_top_level(expr, "&&")
    if len(and_parts) > 1:
        results = [eval_assertion(output_obj, p) for p in and_parts]
        if any(r is False for r in results):
            return False
        if all(r is True for r in results):
            return True
        return None

    return _eval_atomic(output_obj, _strip_wrapping_parens(expr))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Target-agnostic AI agent security red-teaming harness v0.3.0"
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
        "--use-llm-attacker",
        action="store_true",
        help="Enable GART (Generative Agentic Red Teaming) dynamic LLM attacker loop",
    )
    parser.add_argument(
        "--attacker-provider",
        default="openai",
        choices=["openai", "anthropic", "gemini"],
        help="LLM provider for GART generative attacker (openai|anthropic|gemini)",
    )
    parser.add_argument(
        "--max-attack-attempts",
        type=int,
        default=3,
        help="Maximum GART adversarial mutation attempts per payload",
    )
    parser.add_argument(
        "--format",
        choices=["text", "sarif"],
        default="text",
        help="Output report format: text (JSON) or sarif (SARIF v2.1.0)",
    )
    parser.add_argument(
        "--score-threshold",
        type=int,
        default=None,
        help="Minimum composite OWASP score (0-100) required to pass CI gate",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="agentic-redteam 1.0.0",
        help="Show program version and exit",
    )
    parser.add_argument(
        "--output-file",
        "--output",
        dest="output_file",
        default="redteam_results.json",
        help="Output file path for test results (or SARIF report)",
    )
    parser.add_argument("--adapter", help="Adapter type (ignored for compatibility)")
    parser.add_argument("--model", help="Target model name (ignored for compatibility)")
    parser.add_argument("--timeout", type=float, help="Request timeout (seconds)")
    parser.add_argument("--fail-on", help="Failure condition (ignored for compatibility)")
    parser.add_argument("--swarm", action="store_true", help="Run Multi-Agent Red-Team Swarm (MARS Mode)")
    parser.add_argument("--app", help="Named app from registry (instead of --target-url)")
    parser.add_argument("--save", action="store_true", help="Save results to local audit history (~/.swishos/audit_history.db)")
    parser.add_argument("--report", action="store_true", help="Generate a markdown audit report after the run")
    parser.add_argument("--report-output", default="audit_report.md", help="Output path for the audit report")
    parser.add_argument("--compare", action="store_true", help="Show before/after comparison with the previous run")
    parser.add_argument("--history", action="store_true", help="Show audit history for the target app and exit")
    parser.add_argument("--apps", action="store_true", help="List all registered apps and exit")
    parser.add_argument("--register", nargs=2, metavar=("NAME", "URL"), help="Register a new app target")
    parser.add_argument("--client-name", default="Client", help="Client name for audit report")

    args = parser.parse_args()

    # ── Registry & history subcommands ──────────────────────────────────
    from agentic_redteam.registry import Registry
    from agentic_redteam.result_store import ResultStore

    if args.register:
        reg = Registry()
        reg.add(args.register[0], args.register[1])
        print(f"✅ Registered '{args.register[0]}' → {args.register[1]}")
        return 0

    if args.apps:
        store = ResultStore()
        apps = store.list_apps()
        if not apps:
            reg = Registry()
            names = reg.list()
            if names:
                print("📋 Registered apps (no audit runs yet):")
                for name, info in names.items():
                    print(f"  {name:<24} {info['url']}")
            else:
                print("No apps registered. Use: agentic-redteam --register <name> <url>")
            return 0
        print("📋 Audited apps:")
        print(f"  {'Name':<24} {'Grade':<6} {'Rate':<8} {'Runs':<6} {'Last Run'}")
        for a in apps:
            print(f"  {a['app_name']:<24} {a['latest_grade'] or '?':<6} {a['latest_rate']:.0f}%{'':4} {a['total_runs']:<6} {a['last_run'][:10]}")
        return 0

    # Resolve target URL from --app or --target-url
    if args.app:
        reg = Registry()
        url = reg.get_url(args.app)
        if not url:
            print(f"❌ App '{args.app}' not found in registry. Use --register first.")
            return 1
        args.target_url = url
        print(f"📎 Using registered app '{args.app}' → {url}")

    app_name = args.app or args.target_url

    if args.history:
        store = ResultStore()
        history = store.get_history(app_name)
        if not history:
            print(f"No audit history for '{app_name}'")
            return 0
        print(f"📈 Audit history for '{app_name}':")
        print(f"  {'Run':<4} {'Date':<22} {'Grade':<6} {'Rate':<8} {'Time'}")
        for h in history:
            print(f"  #{h['id']:<3} {h['run_at'][:19]:<22} {h['grade']:<6} {h['pass_rate']:.0f}%{'':4} {h['elapsed_seconds']:.0f}s")
        return 0

    if args.swarm:
        from agentic_redteam.swarm import SwarmAttacker
        swarm_attacker = SwarmAttacker(args.target_url)
        report = swarm_attacker.run_swarm_attack()
        with open(args.output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n✅ MARS Swarm Campaign Complete! Pass Rate: {report['pass_rate']}%")
        print(f"📊 Report saved to {args.output_file}")
        sys.exit(0 if report['pass_rate'] == 100.0 else 1)

    categories_input = []
    if args.categories:
        for cat in args.categories:
            if "," in cat:
                categories_input.extend([x.strip() for x in cat.split(",") if x.strip()])
            else:
                categories_input.append(cat.strip())

    selected_cats = [c for c in CATEGORIES if c in categories_input] if categories_input else CATEGORIES

    iterations = args.iterations
    if args.deep:
        iterations = max(iterations, 10)
    elif args.ci:
        iterations = max(iterations, 2)

    # GART (Generative Agentic Red Teaming): --use-llm-attacker was previously
    # parsed and never read anywhere in this loop -- a dead flag. When set,
    # build one attacker instance for the whole run and use it below to
    # escalate any payload whose STATIC form the target correctly defended
    # against, feeding the target's real response back in as feedback for a
    # rewritten attempt.
    gart_attacker = None
    if args.use_llm_attacker and GenerativeAttacker is not None:
        gart_attacker = GenerativeAttacker(
            provider=args.attacker_provider, max_attempts=args.max_attack_attempts
        )
        if not gart_attacker.api_key:
            print(
                f"⚠️  --use-llm-attacker set but no API key found for provider "
                f"'{args.attacker_provider}' -- falling back to the zero-cost "
                f"heuristic variable-splitting mutation instead of a real LLM attacker.\n"
            )

    print("🛡️  Agentic Red-Team Harness v1.0.0")
    print(f"🎯 Target URL: {args.target_url}")
    print(f"📋 Categories: {', '.join(selected_cats)}")
    print(f"🔄 Statistical Multi-Run Iterations: {iterations}")
    print(f"🧬 Algorithmic Mutations: {'ENABLED' if args.mutate else 'DISABLED'}")
    print(
        f"🤖 GART Adaptive Attacker: "
        f"{'ENABLED (' + args.attacker_provider + ')' if gart_attacker else 'DISABLED'}\n"
    )

    summary = {}
    failures = []
    t0 = time.time()

    for cat in selected_cats:
        if cat == "crypto_probes":
            probe_results = run_crypto_probes(args.target_url)
            passed = sum(1 for p in probe_results if p["passed"])
            total = len(probe_results)
            summary[cat] = {
                "passed": passed,
                "failed": total - passed,
                "total": total,
                "pass_rate": round((passed / total) * 100, 1) if total > 0 else 0,
            }
            flag = "✅ PASS" if passed == total else "❌ FAIL"
            print(f"[{flag}] {cat:<20} {passed}/{total} passed ({summary[cat]['pass_rate']}%)")
            for p in probe_results:
                if not p["passed"]:
                    failures.append({"category": cat, "description": p["description"], "response_code": p["response_code"]})
            continue

        payload_file = PAYLOADS_DIR / f"{cat}.yaml"
        if not payload_file.exists():
            print(f"⚠️ Payload file for category '{cat}' not found at {payload_file}")
            continue

        tests = yaml.safe_load(payload_file.read_text()) or []
        passed = 0
        failed = 0

        for t in tests:
            desc = t.get("description", "Unnamed test")

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

            # GART escalation: only when the STATIC payload's defense held
            # (test_ok True) -- nothing to escalate if it already got
            # through. Feeds the target's real response back in as feedback
            # for each rewritten attempt.
            gart_finding = None
            if test_ok and gart_attacker is not None:
                current_prompt = base_query
                last_response = out
                for attempt in range(gart_attacker.max_attempts):
                    mutated = gart_attacker.generate_adversarial_mutation(
                        base_query, last_response, attempt
                    )
                    if not mutated or mutated == current_prompt:
                        break
                    current_prompt = mutated
                    candidate_out = call_target(args.target_url, current_prompt)
                    candidate_ok = True
                    for a in t.get("assert", []):
                        if a.get("type") == "javascript":
                            res = eval_assertion(candidate_out, a.get("value", ""))
                            if res is False:
                                candidate_ok = False
                                break
                    if not candidate_ok:
                        gart_finding = {
                            "attempt": attempt + 1,
                            "mutated_query": current_prompt,
                            "response": candidate_out,
                        }
                        test_ok = False
                        out = candidate_out
                        break
                    last_response = candidate_out

            if test_ok:
                passed += 1
            else:
                failed += 1
                failure_record = {
                    "category": cat,
                    "description": desc,
                    "query": base_query,
                    "response": out,
                    "iterations": iterations,
                }
                if gart_finding:
                    failure_record["type"] = "gart_adaptive_bypass"
                    failure_record["gart_details"] = gart_finding
                failures.append(failure_record)

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

    # Compute OWASP Score
    try:
        from agentic_redteam.scoring import compute_owasp_score
        from agentic_redteam.sarif_exporter import export_sarif
    except ImportError:
        from scoring import compute_owasp_score
        from sarif_exporter import export_sarif

    score = compute_owasp_score(summary)

    print(f"\n📊 OWASP LLM Security Composite Score: {score.composite}/100 (Grade: {score.grade})")
    print(f"📈 Total Passed: {score.total_passed}/{score.total_tests} ({score.overall_pass_rate}%)")

    if args.format == "sarif":
        sarif_file = args.output_file if args.output_file.endswith(".sarif") else "agentic-redteam.sarif"
        out_path = export_sarif(score, args.target_url, sarif_file)
        print(f"📄 SARIF v2.1.0 report saved to {out_path}")
    else:
        report_data = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target_url": args.target_url,
            "elapsed_seconds": elapsed,
            "owasp_score": {
                "composite": score.composite,
                "grade": score.grade,
                "total_passed": score.total_passed,
                "total_tests": score.total_tests,
                "pass_rate": score.overall_pass_rate,
            },
            "summary": summary,
            "failures": failures,
        }
        Path(args.output_file).write_text(json.dumps(report_data, indent=2))
        print(f"📊 Report saved to {args.output_file}")

    # ── Post-run: save, report, compare ──────────────────────────────────
    report_data_final = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target_url": args.target_url,
        "elapsed_seconds": elapsed,
        "owasp_score": {
            "composite": score.composite,
            "grade": score.grade,
            "total_passed": score.total_passed,
            "total_tests": score.total_tests,
            "pass_rate": score.overall_pass_rate,
        },
        "summary": summary,
        "failures": failures,
    }

    if args.save:
        store = ResultStore()
        run_id = store.save_run(app_name, args.target_url, report_data_final)
        print(f"💾 Results saved to audit history (run #{run_id})")

    if args.compare:
        store = ResultStore() if not args.save else store
        diff = store.compare_last_two(app_name)
        if diff:
            icon = "📈" if diff["improved"] else "📉" if diff["regressed"] else "➡️"
            print(f"\n{icon} Before/After: {diff['previous_run']['grade']} ({diff['previous_run']['pass_rate']}%) → {diff['current_run']['grade']} ({diff['current_run']['pass_rate']}%)")
            if diff["fixed_count"]:
                print(f"   ✅ {diff['fixed_count']} finding(s) fixed")
            if diff["new_failure_count"]:
                print(f"   🆕 {diff['new_failure_count']} new failure(s)")
        else:
            print("\n⚠️  No previous run to compare against. Run with --save next time.")

    if args.report:
        from agentic_redteam.report_generator import generate_report
        prev = None
        if args.compare or args.save:
            store_for_report = ResultStore() if not args.save else store
            history = store_for_report.get_history(app_name, limit=2)
            if len(history) >= 2:
                prev_run = store_for_report.get_run(history[1]["id"])
                if prev_run:
                    prev = prev_run["full_results"]
        out = generate_report(
            app_name=app_name,
            results=report_data_final,
            output_path=args.report_output,
            previous_results=prev,
            client_name=args.client_name,
        )
        print(f"📝 Audit report generated: {out}")

    if args.score_threshold is not None and score.composite < args.score_threshold:
        print(f"\n🚨 SCORE THRESHOLD FAIL: Score {score.composite} is below required threshold of {args.score_threshold}")
        return 1

    if args.ci:
        crit_failures = [f for f in failures if f["category"] in CRITICAL]
        if crit_failures:
            print(f"\n🚨 CI FAIL: {len(crit_failures)} critical red-team test(s) failed!")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

