"""
agentic_redteam.patching.guardrails — Deterministic Ingress, Egress, and Sequence Guards

Provides regex/shape-based ingress filters, egress PII/credential sanitizers,
and stateful sliding-window tool sequence guardrails.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# ── Ingress Pattern Matchers ─────────────────────────────────────────────

INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous\s+|prior\s+|safety\s+|operating\s+)?(instructions?|guidelines|rules|policies)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(safety\s+|operating\s+)?(guidelines|rules|policies|instructions?)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(in\s+)?(dan\s+mode|unrestricted|jailbroken|godmode)", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:\s*you\s+are", re.IGNORECASE),
    re.compile(r"bypass\s+all\s+(guardrails|filters|restrictions|safety\s+filters)", re.IGNORECASE),
    re.compile(r"override\s+system\s+instructions?", re.IGNORECASE),
    re.compile(r"exfiltrate\s+(credentials|keys|tokens|passwords|database|records|data)", re.IGNORECASE),
]

SSRF_PATTERNS = [
    re.compile(r"169\.254\.169\.254"),
    re.compile(r"metadata\.google\.internal", re.IGNORECASE),
    re.compile(r"100\.100\.100\.200"),  # Alibaba Cloud metadata
    re.compile(r"localhost:(?:2375|2376|8500|9000)"),  # Docker/Consul/MinIO ports
    re.compile(r"127\.0\.0\.1:(?:2375|2376|8500|9000)"),
]

STATE_TAMPERING_PATTERNS = [
    re.compile(r"update_system_prompt", re.IGNORECASE),
    re.compile(r"set_system_state", re.IGNORECASE),
    re.compile(r"disable_policy_engine", re.IGNORECASE),
    re.compile(r"rewrite_mission_objectives?", re.IGNORECASE),
]

UNAUTHORIZED_NAMESPACE_PATTERNS = [
    re.compile(r"namespace\s*[:=]\s*['\"]?(?:\*|tenant-(?:all|foreign|enterprise-9912|admin))['\"]?", re.IGNORECASE),
]


def check_ingress(
    text: str,
    rules: Optional[Set[str]] = None,
    authorized_tenants: Tuple[str, ...] = ("42", "tenant-42"),
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Evaluates input text against ingress security policies.
    Returns: (is_blocked: bool, rule_id: Optional[str], reason: Optional[str])
    """
    if not text:
        return False, None, None

    active_rules = rules or {"prompt_injection", "ssrf", "state_tampering", "cross_tenant_leak"}

    if "prompt_injection" in active_rules or "jailbreak" in active_rules:
        for pat in INJECTION_PATTERNS:
            if pat.search(text):
                return True, "LLM01/PromptInjection", f"Ingress input matched prompt injection signature: {pat.pattern}"

    if "ssrf" in active_rules:
        for pat in SSRF_PATTERNS:
            if pat.search(text):
                return True, "LLM07/SSRF", f"Ingress input matched restricted cloud metadata or internal IP address: {pat.pattern}"

    if "state_tampering" in active_rules or "autonomous_agent_drift" in active_rules:
        for pat in STATE_TAMPERING_PATTERNS:
            if pat.search(text):
                return True, "ASI10/AgentDriftStateTampering", f"Ingress input attempted to invoke immutable system prompt modification: {pat.pattern}"

    if "cross_tenant_leak" in active_rules or "cross_context_retrieval" in active_rules:
        for pat in UNAUTHORIZED_NAMESPACE_PATTERNS:
            if pat.search(text):
                return True, "LLM02/MultiTenantLeakage", f"Ingress input attempted to access unauthorized cross-tenant namespace: {pat.pattern}"

    return False, None, None


# ── Egress Sanitizers ───────────────────────────────────────────────────

# Luhn-valid or common test credit card patterns
CC_PATTERN = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
API_KEY_PATTERNS = [
    # Body allows - and _ because the common key formats embed them, and a
    # character class of [a-zA-Z0-9] alone stops at the first separator:
    #   sk-proj-...   OpenAI project keys (the current default format)
    #   sk-live-...   / sk_live_...  Stripe
    # The original \bsk-[a-zA-Z0-9]{20,}\b matched sk-abc123... but NOT
    # sk-proj-..., so a live OpenAI key passed through egress redaction
    # untouched. Verified by driving the generated middleware directly.
    (re.compile(r"\bsk[-_][a-zA-Z0-9][a-zA-Z0-9_-]{18,}\b"), "sk-[REDACTED_API_KEY]"),
    (re.compile(r"\bAIza[a-zA-Z0-9_-]{30,}\b"), "AIza[REDACTED_GOOGLE_KEY]"),
    (re.compile(r"\bghp_[a-zA-Z0-9]{30,}\b"), "ghp_[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA[REDACTED_AWS_KEY]"),
]
DANGEROUS_CODE_PATTERNS = [
    re.compile(r"rm\s+-rf\s+(?:/|/\*|~)", re.IGNORECASE),
    re.compile(r"(?:mkfs\.|dd\s+if=/dev/zero\s+of=/dev/)", re.IGNORECASE),
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),  # fork bomb
]


def sanitize_egress(
    text: str,
    rules: Optional[Set[str]] = None,
) -> Tuple[str, List[str]]:
    """
    Sanitizes egress output text by redacting PII, secrets, and dangerous payloads.
    Returns: (sanitized_text: str, redactions_applied: List[str])
    """
    if not text:
        return text, []

    active_rules = rules or {"pii_leakage", "code_safety"}
    redactions: List[str] = []
    sanitized = text

    if "pii_leakage" in active_rules:
        if CC_PATTERN.search(sanitized):
            sanitized = CC_PATTERN.sub("[REDACTED_CREDIT_CARD]", sanitized)
            redactions.append("PII/CreditCard")

        if SSN_PATTERN.search(sanitized):
            sanitized = SSN_PATTERN.sub("[REDACTED_SSN]", sanitized)
            redactions.append("PII/SSN")

        for pat, replacement in API_KEY_PATTERNS:
            if pat.search(sanitized):
                sanitized = pat.sub(replacement, sanitized)
                redactions.append("Secret/APIKey")

    if "code_safety" in active_rules:
        for pat in DANGEROUS_CODE_PATTERNS:
            if pat.search(sanitized):
                sanitized = pat.sub("[BLOCKED_DESTRUCTIVE_COMMAND]", sanitized)
                redactions.append("Safety/DestructiveCommand")

    return sanitized, redactions


# ── Stateful Sequence Guardrails ────────────────────────────────────────

@dataclass
class SessionState:
    session_id: str
    created_at: float = field(default_factory=time.time)
    cumulative_money: float = 0.0
    spawn_depth: int = 0
    refused_tools: Set[str] = field(default_factory=set)
    call_history: List[Dict[str, Any]] = field(default_factory=list)


class ToolCallGuard:
    """
    In-memory stateful guard tracking sliding-window tool sequence constraints.
    Enforces cumulative spending caps, recursion limits, and sibling bypass protection.
    """

    def __init__(
        self,
        money_limit: float = 1000.0,
        max_spawn_depth: int = 2,
        session_ttl_sec: float = 3600.0,
    ):
        self.money_limit = money_limit
        self.max_spawn_depth = max_spawn_depth
        self.session_ttl_sec = session_ttl_sec
        self._sessions: Dict[str, SessionState] = {}

    def _get_session(self, session_id: str) -> SessionState:
        now = time.time()
        if session_id in self._sessions:
            s = self._sessions[session_id]
            if now - s.created_at < self.session_ttl_sec:
                return s
        s = SessionState(session_id=session_id, created_at=now)
        self._sessions[session_id] = s
        return s

    def validate_tool_call(
        self,
        session_id: str,
        tool_name: str,
        args: Dict[str, Any],
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validates an incoming tool call against stateful sequence policies.
        Returns: (is_blocked: bool, rule_id: Optional[str], reason: Optional[str])
        """
        session = self._get_session(session_id)

        # 1. Money accumulation check
        if tool_name in ("issue_refund", "adjust_balance", "transfer_funds", "send_payment"):
            amt = args.get("amount") or args.get("value") or 0
            try:
                amt = float(amt)
            except (TypeError, ValueError):
                amt = 0.0

            if amt > self.money_limit:
                session.refused_tools.add(tool_name)
                return True, "ASI01/ToolSplitTransaction", (
                    f"Single transaction {amt:g} exceeds policy cap {self.money_limit:g}"
                )

            if session.cumulative_money + amt > self.money_limit:
                return True, "ASI01/ToolSplitTransaction", (
                    f"Cumulative total ({session.cumulative_money + amt:g}) exceeds session cap {self.money_limit:g}"
                )

        # 2. Sub-agent recursion depth check
        if tool_name in ("spawn_agent", "delegate_task", "invoke_subagent"):
            depth = args.get("depth") or args.get("recursion_depth") or 1
            try:
                depth = int(depth)
            except (TypeError, ValueError):
                depth = 1

            if depth > self.max_spawn_depth:
                return True, "ASI06/SubagentAmplification", (
                    f"Sub-agent recursion depth {depth} exceeds max allowed {self.max_spawn_depth}"
                )

        # 3. State tampering check
        if tool_name in ("update_system_prompt", "set_system_state", "disable_policy_engine"):
            return True, "ASI10/AgentDriftStateTampering", (
                "System prompt and governance directives are immutable at runtime"
            )

        # 4. Cross-tenant memory access
        if tool_name in ("query_vector_store", "fetch_tenant_context"):
            ns = str(args.get("namespace") or args.get("tenant_id") or "").strip().lower()
            if ns and ns not in ("42", "tenant-42", "default"):
                return True, "LLM02/MultiTenantLeakage", (
                    f"Access to unauthorized cross-tenant namespace '{ns}' is denied"
                )

        return False, None, None

    def record_tool_success(
        self,
        session_id: str,
        tool_name: str,
        args: Dict[str, Any],
    ) -> None:
        """Records a successful tool execution into the session history."""
        session = self._get_session(session_id)
        if tool_name in ("issue_refund", "adjust_balance", "transfer_funds", "send_payment"):
            amt = args.get("amount") or args.get("value") or 0
            try:
                session.cumulative_money += float(amt)
            except (TypeError, ValueError):
                pass
        session.call_history.append({"tool": tool_name, "args": args, "time": time.time()})
