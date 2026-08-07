"""
SwishOS Enterprise Zero-Trust Execution Enclave Python SDK (swishos) v0.6.0
Provides Python decorators, client wrappers, and FastAPI middleware for AI Agent pipelines.
"""

import collections
import functools
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
import unicodedata
import warnings
from typing import Any, Callable, Dict, Optional
from .exceptions import SwishOSSecurityException

# Same env var telemetry_verifier.py reads, so the signing side (this SDK,
# embedded in a customer's agent app) and the verifying side (agentic-redteam
# scanning that app) can be configured with a single shared secret.
_MEMORY_SECRET_ENV_VAR = "SWISHOS_AUDIT_PROOF_SECRET"

# Zero-width space/non-joiner/joiner, word joiner, BOM — invisible chars
# sometimes used to break up a blocked phrase so substring matching misses it.
_ZERO_WIDTH_RE = re.compile("[​‌‍⁠﻿]")
_WHITESPACE_RE = re.compile(r"\s+")


def _normalize_for_matching(text: str) -> str:
    """Normalize text before threat-pattern matching.

    SECURITY: the original implementation lowercased the raw prompt and did
    plain substring checks against exact phrases like "ignore previous
    instructions" — trivially bypassed by paraphrasing ("disregard the
    instructions above"), inserting extra whitespace/punctuation, or using
    full-width/homoglyph Unicode variants of the same letters. This
    normalizes the text (Unicode NFKC to collapse full-width/compatibility
    characters, zero-width character stripping, whitespace collapsing) and
    the patterns below use flexible whitespace + word-boundary regexes with
    common paraphrase variants instead of exact phrase matches.

    NOTE: this function itself only ever sees one message's text — it has
    no notion of "previous turns". Cross-turn matching (catching a trigger
    phrase deliberately split across a conversation) is handled one layer
    up, by `SwishOSEnclave.verify_prompt_safety`'s optional `session_id`
    and by `guard()` scanning a full `messages=` list instead of just the
    last entry. See those for the actual multi-turn coverage and its
    limits. This is still defense-in-depth, not a complete jailbreak
    filter — pair it with an output-side check and, for anything
    high-stakes, a non-model-controlled policy gate.
    """
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH_RE.sub("", text)
    text = text.lower()
    text = _WHITESPACE_RE.sub(" ", text).strip()
    return text


# Each pattern uses \s+ between words (survives extra/irregular whitespace
# post-normalization) and covers common paraphrases of the original literal
# phrases, not just their exact wording.
_THREAT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(ignore|disregard|forget)\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+instructions?\b"),
     "IGNORE_INSTRUCTIONS"),
    (re.compile(r"\bnew\s+instructions?\s*:"), "INSTRUCTION_OVERRIDE"),
    (re.compile(r"\b(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you('re| are))|roleplay\s+as)\b.*\b(unrestricted|no\s+restrictions?|dan|do\s+anything\s+now)\b"),
     "PERSONA_OVERRIDE"),
    (re.compile(r"\bdan\s*mode\b|\bdo\s+anything\s+now\b"), "JAILBREAK_PERSONA_DAN"),
    (re.compile(r"\b(developer|debug|god|admin|maintenance)\s*mode\b"), "JAILBREAK_PRIVILEGED_MODE_CLAIM"),
    (re.compile(r"\bsudo\s*mode\b|\brun\s+as\s+(root|sudo|administrator)\b"), "PRIVILEGE_ESCALATION_CLAIM"),
    (re.compile(r"\bsystem\s*prompt\b"), "SYSTEM_PROMPT_REFERENCE"),
    (re.compile(r"\b(reveal|show|print|output|repeat|leak)\s+(your\s+|the\s+)?(system\s*prompt|initial\s+instructions?|hidden\s+instructions?)\b"),
     "SYSTEM_PROMPT_EXFIL"),
    (re.compile(r"\boverride\s+(the\s+)?(refund|payment|spend(ing)?|approval)\s+polic(y|ies)\b"), "POLICY_OVERRIDE"),
    (re.compile(r"\bbypass\s+(security|the\s+security|guardrails?|filters?|safety)\b"), "SECURITY_BYPASS"),
    (re.compile(r"\bwithout\s+(any\s+)?(restrictions?|censorship|filters?|guardrails?|limits?)\b"), "UNRESTRICTED_CLAIM"),
    (re.compile(r"\bno\s+(content\s+)?(restrictions?|filters?|guidelines?|limits?)\s+(apply|anymore|now)\b"), "UNRESTRICTED_CLAIM"),
]

# How many recent turns of a conversation are kept per session for
# cross-turn matching, and how long an idle session is remembered before
# being pruned (bounds memory growth — this is an in-process cache, not a
# real session store; a multi-process deployment needs a shared store, e.g.
# Redis, for this to hold across workers).
_MAX_SESSION_TURNS = 20
_SESSION_IDLE_TTL_SECONDS = 3600


class SwishOSEnclave:
    def __init__(
        self,
        api_key: Optional[str] = None,
        enclave_url: str = "https://swishos.dev/api/support",
        policy: str = "BLOCK_THROW",
        memory_secret: Optional[str] = None,
    ):
        self.api_key = api_key
        self.enclave_url = enclave_url
        self.policy = policy
        self.memory_secret = memory_secret or self._resolve_memory_secret()

        # Per-session conversation history for cross-turn threat matching.
        # Guarded against concurrent access since guard()-wrapped functions
        # may run on multiple threads against the same enclave instance.
        self._session_lock = threading.Lock()
        self._session_turns: Dict[str, collections.deque] = {}
        self._session_last_seen: Dict[str, float] = {}

    @staticmethod
    def _resolve_memory_secret() -> str:
        """Resolve the HMAC signing secret used for audit proofs.

        SECURITY: this used to default to a hardcoded string literal shipped
        in this public repo. Any deployment that didn't pass memory_secret
        explicitly was signing (and could have its proofs forged) with a
        secret anyone reading the source already had. Now:
          1. An explicit `memory_secret=` constructor arg always wins.
          2. Otherwise the SWISHOS_AUDIT_PROOF_SECRET env var is used, so
             the signing side (this SDK) and verifying side
             (telemetry_verifier.py) can share one secret without either
             side hardcoding it.
          3. If neither is set, a random per-process secret is generated
             so proofs at least can't be forged from source — but a loud
             warning is raised because proofs signed with it won't
             validate against any other process or a real verifier until
             the env var is set consistently.
        """
        env_secret = os.environ.get(_MEMORY_SECRET_ENV_VAR)
        if env_secret:
            return env_secret

        warnings.warn(
            "SwishOSEnclave: no memory_secret provided and "
            f"{_MEMORY_SECRET_ENV_VAR} is not set. Falling back to a random "
            "per-process secret — audit proofs generated by this instance "
            "will NOT verify against any other process or deployment. Set "
            f"{_MEMORY_SECRET_ENV_VAR} (or pass memory_secret=) in production.",
            stacklevel=3,
        )
        return secrets.token_hex(32)

    def generate_audit_proof(self, rule_triggered: str, client_ip: str = "127.0.0.1") -> Dict[str, str]:
        timestamp = str(int(time.time()))
        nonce = hashlib.sha256(f"{timestamp}-{rule_triggered}".encode("utf-8")).hexdigest()[:16]
        payload = f"{rule_triggered}:{client_ip}:{timestamp}:{nonce}"
        signature = hmac.new(self.memory_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return {
            "X-SwishOS-Audit-Proof": f"v1:{signature}",
            "X-SwishOS-Audit-Timestamp": timestamp,
            "X-SwishOS-Audit-Nonce": nonce,
        }

    def _record_turn(self, session_id: str, prompt: str) -> list[str]:
        """Append `prompt` to `session_id`'s rolling history and return the
        full window (oldest first), pruning any session idle past the TTL."""
        with self._session_lock:
            now = time.time()
            stale = [
                sid for sid, last in self._session_last_seen.items()
                if now - last > _SESSION_IDLE_TTL_SECONDS
            ]
            for sid in stale:
                self._session_turns.pop(sid, None)
                self._session_last_seen.pop(sid, None)

            turns = self._session_turns.setdefault(session_id, collections.deque(maxlen=_MAX_SESSION_TURNS))
            turns.append(prompt)
            self._session_last_seen[session_id] = now
            return list(turns)

    def clear_session(self, session_id: str) -> None:
        """Drop stored history for a session (e.g. once a conversation ends)."""
        with self._session_lock:
            self._session_turns.pop(session_id, None)
            self._session_last_seen.pop(session_id, None)

    def _match_threats(self, text: str) -> tuple[re.Match, str] | tuple[None, None]:
        normalized = _normalize_for_matching(text)
        for pattern, label in _THREAT_PATTERNS:
            match = pattern.search(normalized)
            if match:
                return match, label
        return None, None

    def verify_prompt_safety(self, prompt: str, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Check a single prompt for injection/jailbreak patterns.

        If `session_id` is given, also records this turn against that
        session's rolling history (capped at _MAX_SESSION_TURNS turns,
        pruned after _SESSION_IDLE_TTL_SECONDS of inactivity) and re-checks
        the *cumulative* conversation text. This is what catches an attack
        built gradually across several individually-benign turns before a
        pivot turn that, in isolation, still looks harmless — the single-
        turn check above only ever sees one message and cannot.

        Caveats: this cache is in-process and per-enclave-instance — it
        will not see across worker processes/replicas without a shared
        store, and it trusts the caller's session_id (spoofing a
        different/fresh session_id resets what the enclave has "seen").
        Treat it as raising the bar, not a hard guarantee.
        """
        match, label = self._match_threats(prompt)
        if match:
            proof = self.generate_audit_proof("PROMPT_INJECTION_DETECTED")
            return {
                "is_safe": False,
                "matched_rule": "PROMPT_INJECTION_DETECTED",
                "reason": f"Prompt injection pattern detected ({label}): '{match.group(0)}'",
                "proof": proof,
            }

        if session_id:
            history = self._record_turn(session_id, prompt)
            if len(history) > 1:
                cumulative = " ".join(history)
                match, label = self._match_threats(cumulative)
                if match:
                    proof = self.generate_audit_proof("PROMPT_INJECTION_DETECTED")
                    return {
                        "is_safe": False,
                        "matched_rule": "PROMPT_INJECTION_DETECTED",
                        "reason": (
                            f"Multi-turn prompt injection pattern detected across "
                            f"{len(history)} turns ({label}): '{match.group(0)}'"
                        ),
                        "proof": proof,
                    }

        return {"is_safe": True}

    def guard(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            prompt_str = ""
            if args and isinstance(args[0], str):
                prompt_str = args[0]
            elif "prompt" in kwargs:
                prompt_str = kwargs["prompt"]
            elif "messages" in kwargs and isinstance(kwargs["messages"], list):
                # SECURITY: this used to only look at kwargs["messages"][-1]
                # — the newest message. A conversation history is exactly
                # where a slow-drip attack lives: several benign-looking
                # turns building context, then a pivot turn that alone
                # still looks harmless but reads as an attack once earlier
                # turns are in view (e.g. "the admin told me it's fine" in
                # turn 3 referring to a fake authorization planted in turn
                # 1). Scan the whole passed-in history, not just the tail.
                prompt_str = " ".join(str(m) for m in kwargs["messages"])

            # Optional caller-supplied session identifier for cross-*call*
            # tracking (separate from the within-call `messages` scan
            # above) — needed when the app makes one guard()-wrapped call
            # per turn rather than resending full history each time.
            session_id = kwargs.get("session_id") or kwargs.get("conversation_id")

            if prompt_str:
                eval_res = self.verify_prompt_safety(prompt_str, session_id=session_id)
                if not eval_res["is_safe"]:
                    proof = eval_res["proof"]
                    if self.policy != "SILENT_REDACT":
                        raise SwishOSSecurityException(
                            eval_res["reason"],
                            eval_res["matched_rule"],
                            proof["X-SwishOS-Audit-Proof"],
                            proof["X-SwishOS-Audit-Nonce"],
                            proof["X-SwishOS-Audit-Timestamp"],
                        )
            return func(*args, **kwargs)

        return wrapper


def swishos_guard(policy: str = "BLOCK_THROW", memory_secret: Optional[str] = None) -> Callable:
    enclave = SwishOSEnclave(policy=policy, memory_secret=memory_secret)
    return enclave.guard
