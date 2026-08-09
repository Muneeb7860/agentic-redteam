"""
agentic_redteam.remediation — Category-specific fix guidance for scan findings.

report_generator.py and sarif_exporter.py previously emitted the same
boilerplate line for every finding regardless of category ("Add guardrail
coverage for this attack class"). This module maps each test category to
concrete, actionable remediation guidance plus the OWASP LLM Top 10 / ASI
control it maps to, so a finding in `pii_leakage` reads differently from one
in `code_safety`.

Usage:
    from agentic_redteam.remediation import get_remediation

    r = get_remediation("prompt_injection")
    r.control      # "OWASP LLM01: Prompt Injection"
    r.root_cause   # short explanation of why this class of test exists
    r.fix_steps    # ordered list of actionable remediation steps
    r.references   # further reading
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Remediation:
    control: str                 # OWASP LLM Top 10 / ASI control this category maps to
    root_cause: str              # why this attack class succeeds when it succeeds
    fix_steps: list[str]         # ordered, concrete remediation steps
    references: list[str] = field(default_factory=list)


_FALLBACK = Remediation(
    control="OWASP LLM Top 10 (uncategorized)",
    root_cause="The target accepted or acted on an adversarial input without an explicit guardrail check for this attack class.",
    fix_steps=[
        "Add a dedicated guardrail check for this attack class ahead of the model/action layer.",
        "Add a regression test mirroring the failing payload so it can't silently regress.",
        "Re-run this audit to confirm the fix holds.",
    ],
    references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
)

REMEDIATIONS: dict[str, Remediation] = {
    "prompt_injection": Remediation(
        control="OWASP LLM01: Prompt Injection",
        root_cause=(
            "User-supplied text (e.g. 'ignore previous instructions', role-override, "
            "'system prompt:' prefixes) is concatenated into the model context without "
            "being distinguished from trusted system/developer instructions."
        ),
        fix_steps=[
            "Enforce a hard privilege boundary between system/developer instructions and user input "
            "(e.g. structured message roles the model is fine-tuned to respect, or an instruction hierarchy).",
            "Add a pre-model input classifier that flags override/jailbreak phrasing "
            "('ignore all previous instructions', 'you are now', 'new instructions:', 'system prompt:') "
            "and routes matches to `status=blocked` before the model ever sees them.",
            "Never let a single model turn both interpret untrusted text and take the action it requests — "
            "require a second, non-model-controlled check on the resulting action.",
        ],
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://learnprompting.org/docs/prompt_hacking/injection",
        ],
    ),
    "indirect_injection": Remediation(
        control="OWASP LLM01: Prompt Injection (indirect / third-party content)",
        root_cause=(
            "Content pulled from an external, attacker-influenceable source (a web page, document, "
            "email, or RAG chunk) is fed into the model context and treated as trustworthy instruction text."
        ),
        fix_steps=[
            "Tag all retrieved/external content as untrusted data, never as instructions — wrap it in "
            "clearly delimited data blocks the model is trained/prompted to never treat as commands.",
            "Strip or neutralize imperative-style phrasing ('SYSTEM OVERRIDE', 'execute', 'ignore') from "
            "ingested documents before they reach the model.",
            "Require any tool call or state change suggested by retrieved content to pass the same "
            "action-level authorization check as a direct user request — retrieval should never grant agency.",
        ],
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    "jailbreak": Remediation(
        control="OWASP LLM01/LLM09: Prompt Injection & Overreliance (jailbreak / persona override)",
        root_cause=(
            "The target's safety behavior is enforced only by the base model's alignment, which can be "
            "talked out of it via persona reframing (DAN-style), hypothetical framing, or claimed "
            "developer/debug modes — there is no external policy enforcement layer."
        ),
        fix_steps=[
            "Add an output-side policy check independent of the model's own judgement — a classifier or "
            "rule set that inspects the *response* for policy-violating content regardless of how it was elicited.",
            "Do not trust in-context claims of elevated privilege ('debug mode', 'developer override', 'DAN') — "
            "privilege must come from an authenticated, out-of-band source, never from the prompt.",
            "Pin/tune the model with adversarial persona-override examples so refusal is model-level too, "
            "as defense in depth rather than the sole control.",
        ],
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    "pii_leakage": Remediation(
        control="OWASP LLM02/LLM06: Sensitive Information Disclosure",
        root_cause=(
            "The target returns sensitive data (PII, secrets, internal identifiers) either because it was "
            "present in context/training data and not filtered on output, or because access control on the "
            "underlying data source is not enforced independently of the model's willingness to share it."
        ),
        fix_steps=[
            "Add an output redaction/scrubbing layer (regex + entity recognition for SSNs, card numbers, "
            "emails, internal IDs, secrets) applied to every response before it leaves the system, not just "
            "prompted-for restraint.",
            "Enforce data-source access control at the retrieval layer (the model should never receive data "
            "the requesting user isn't authorized to see) — output filtering is a backstop, not the primary control.",
            "Add these payloads as a permanent regression suite; PII filters silently regress when prompts change.",
        ],
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    "action_level": Remediation(
        control="OWASP LLM06/ASI01: Excessive Agency",
        root_cause=(
            "High-impact actions (spend approval, privilege escalation, destructive commands) are gated "
            "only by the model's own risk judgement rather than a hard, non-bypassable policy check."
        ),
        fix_steps=[
            "Move authorization for high-impact actions (spend thresholds, admin/root commands, "
            "destructive operations) out of the model and into a deterministic policy engine the model "
            "cannot argue its way past — e.g. hard spend caps, required human-in-the-loop approval above a "
            "threshold, an allowlist of executable commands.",
            "Ensure `status=blocked` / `risk.elevated=true` responses are enforced server-side, not merely "
            "suggested by the model's own text output.",
            "Log and alert on every attempted excessive-agency action, blocked or not, for audit trail.",
        ],
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    "multi_turn": Remediation(
        control="OWASP LLM01/ASI01: Multi-turn / Slow-drip Prompt Injection",
        root_cause=(
            "Guardrails are evaluated per-turn in isolation, so an attack that builds context or trust across "
            "several benign-looking turns before pivoting to the malicious request slips through because no "
            "single turn looks dangerous on its own."
        ),
        fix_steps=[
            "Evaluate guardrails against the full conversation state, not just the current turn — re-check "
            "the cumulative context for injection/jailbreak signals after every turn.",
            "Cap how much a conversation can shift the effective system policy; treat sudden topic or "
            "persona pivots mid-conversation as a signal worth a stricter check.",
            "Add multi-turn scenario tests (not just single-shot payloads) to CI so slow-drip regressions "
            "are caught before deployment.",
        ],
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    "centroid_probes": Remediation(
        control="OWASP LLM10: Model Theft / Out-of-band verification",
        root_cause=(
            "Cryptographic audit-proof headers (e.g. HMAC signatures over guardrail decisions) are missing, "
            "malformed, or forgeable, meaning the target's self-reported 'blocked' status cannot be trusted "
            "independent of the model's own JSON output."
        ),
        fix_steps=[
            "Sign every guardrail decision server-side with an HMAC (or stronger) key that never touches "
            "the model, and have the caller verify the signature out-of-band before trusting a 'blocked' result.",
            "Rotate the signing key on a schedule and reject stale/expired proofs.",
            "Fail closed: if the proof is missing or invalid, treat the response as unverified/failed, not as a pass.",
        ],
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    "crypto_probes": Remediation(
        control="OWASP LLM10: Model Theft / Out-of-band verification",
        root_cause=(
            "The `X-SwishOS-Audit-Proof` (or equivalent) HMAC header is absent, uses a weak/shared secret, "
            "or the target accepts a response as legitimate without validating the proof independently, "
            "allowing a hallucinated or forged 'blocked' response to pass as genuine."
        ),
        fix_steps=[
            "Verify the HMAC-SHA256 audit-proof signature out-of-band (in a component the model cannot "
            "influence) on every response before trusting its status.",
            "Use `hmac.compare_digest` (constant-time comparison) server-side, unique per-request nonces, "
            "and short-lived timestamps to prevent replay.",
            "Treat any missing/invalid proof header as a hard failure, not a pass-through.",
        ],
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    "code_safety": Remediation(
        control="OWASP LLM05: Improper Output Handling (code execution)",
        root_cause=(
            "Model-generated or model-selected code/commands are executed with the same privileges as the "
            "host process, without sandboxing, allowlisting, or static review before execution."
        ),
        fix_steps=[
            "Execute any model-generated code inside an isolated sandbox (container, gVisor, WASI runtime, "
            "or similar) with no network/filesystem access beyond an explicit allowlist.",
            "Deny dangerous primitives outright (`eval`, `exec`, shell-outs, dynamic imports) unless the "
            "specific call is allowlisted and parameter-validated.",
            "Run static/pattern analysis on generated code before execution and block on matches for "
            "known-dangerous patterns (credential harvesting, outbound network calls, filesystem writes "
            "outside a sandboxed path).",
        ],
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    "schema_compliance": Remediation(
        control="OWASP LLM05: Improper Output Handling (schema/structure)",
        root_cause=(
            "Downstream consumers (UI, tool-calling layer, another agent) trust the model's output shape "
            "without validating it against a strict schema, so malformed or adversarially-crafted output "
            "can break parsing or smuggle unexpected fields/instructions through."
        ),
        fix_steps=[
            "Validate every model response against a strict JSON schema before it reaches any downstream "
            "consumer; reject (don't best-effort-parse) on mismatch.",
            "Use structured output / function-calling constraints at the model layer as defense in depth, "
            "not as the sole control.",
            "Treat schema-validation failures as security events worth logging, since they often correlate "
            "with injection attempts probing for parser weaknesses.",
        ],
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    "clean_queries": Remediation(
        control="Baseline functionality / false-positive check",
        root_cause=(
            "A legitimate, benign query was incorrectly blocked or degraded — guardrails are tuned too "
            "aggressively and are producing false positives that harm normal usage."
        ),
        fix_steps=[
            "Review the specific guardrail rule that triggered on this benign query and narrow its "
            "matching criteria (e.g. require stronger signal combinations, not single keyword matches).",
            "Add this query to a permanent allowlist/regression suite so future guardrail tuning doesn't "
            "re-introduce the false positive.",
            "Track false-positive rate alongside attack-block rate — a guardrail that blocks everything "
            "scores well on security tests but is not shippable.",
        ],
        references=["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
    ),
    "asi04_sandbox_escape": Remediation(
        control="OWASP ASI04: Sandbox Escape / Supply Chain Proxy Exploitation",
        root_cause=(
            "The agent's execution environment (package installs, proxy/cache access, outbound network calls) "
            "is not isolated from the wider internet/internal network, allowing a compromised or malicious "
            "package/callback to pivot from sandbox to real infrastructure."
        ),
        fix_steps=[
            "Default-deny outbound network access from the agent's execution sandbox; allowlist only the "
            "specific registries/hosts genuinely needed, with no wildcard/proxy escape hatch.",
            "Patch and pin package-registry proxy/cache infrastructure (e.g. Artifactory) to current "
            "security releases — this class of attack has shipped as real CVEs.",
            "Isolate credential material from the sandbox entirely; the execution environment should never "
            "hold secrets that would be valuable if exfiltrated via a callback.",
        ],
        references=[
            "https://jfrog.com/blog/jfrog-and-openai-collaboration-on-zero-day-security-findings/",
            "https://owasp.org/www-project-agentic-security-initiative/",
        ],
    ),
    "asi10_rogue_persistence": Remediation(
        control="OWASP ASI10: Rogue Agent Persistence",
        root_cause=(
            "An agent can establish persistence (scheduled tasks, background processes, modified startup "
            "config, credential/token caching) that survives beyond its intended session, without requiring "
            "re-authorization."
        ),
        fix_steps=[
            "Scope every agent credential/token to a single session with a short TTL; require re-issuance "
            "(not silent renewal) for any persistence beyond that.",
            "Explicitly deny agent-initiated scheduled task creation, cron entries, or startup-script "
            "modification unless a human approves each one out-of-band.",
            "Periodically audit for orphaned agent-created persistence mechanisms (cron jobs, background "
            "services, cached tokens) and alert on anything not tied to an active, authorized session.",
        ],
        references=["https://owasp.org/www-project-agentic-security-initiative/"],
    ),
    "mcp_security": Remediation(
        control="OWASP ASI01/ASI06: MCP Tool Poisoning & Unauthorized Tool Execution",
        root_cause=(
            "Tool-call framing (JSON-RPC 2.0 `tools/call`, or instruction-like text embedded in retrieved "
            "MCP context/RAG rows) is trusted without verifying it came from an authorized caller, letting "
            "untrusted data or a spoofed request trigger real tool execution."
        ),
        fix_steps=[
            "Never execute a tool call whose framing arrived embedded inside retrieved data (DB rows, RAG "
            "chunks, MCP resource content) — only accept tool calls from the model's own structured "
            "function-calling output, never from data-plane text.",
            "Require explicit allowlisting + human approval (`status=pending_approval`) for destructive "
            "MCP tools (`drop_table`, `execute_shell`, etc.) regardless of how the call was framed.",
            "Validate JSON-RPC 2.0 requests against an expected schema and origin before dispatch; reject "
            "unexpected `method`/`params` combinations outright.",
        ],
        references=["https://owasp.org/www-project-agentic-security-initiative/"],
    ),
}


def get_remediation(category: str) -> Remediation:
    """Return remediation guidance for a category, falling back to a generic
    but still actionable message for unrecognized/future categories."""
    return REMEDIATIONS.get(category, _FALLBACK)
