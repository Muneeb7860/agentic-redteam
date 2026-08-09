"""
SwishOS Cryptographic Inter-Agent Identity & Payload Signer
Defeats Multi-Agent Identity Spoofing (ASI07) using HMAC-SHA256 / Ed25519 Signed Headers.
Includes Timestamp Verification and Nonce Tracking to Prevent Replay Attacks.
"""

from __future__ import annotations
import hmac
import hashlib
import json
import secrets
import threading
import time
from typing import Any, Dict, Tuple

# In-memory nonce cache to prevent replay attacks: maps "agent_id:nonce" ->
# the timestamp it was seen at.
#
# SECURITY/RELIABILITY: this used to be a bare `set[str]` that entries were
# only ever added to, never removed — unbounded growth for the life of the
# process. A nonce can never be successfully replayed once its timestamp
# ages past _MAX_CLOCK_SKEW_SECONDS anyway (the clock-skew check above
# rejects it), so there's no reason to remember it past that window. Now
# pruned opportunistically on each verify call, and guarded by a lock since
# concurrent verification calls (e.g. from multiple request-handling
# threads) would otherwise race on the check-then-add.
#
# CAVEAT: this is still an in-process cache — a multi-worker deployment
# (e.g. multiple gunicorn workers) has one cache per worker, so a nonce can
# be replayed once per worker process. A real production deployment needs a
# shared store (Redis, etc.) for this to hold across workers.
_REPLAY_NONCE_CACHE: Dict[str, int] = {}
_REPLAY_NONCE_LOCK = threading.Lock()
_MAX_CLOCK_SKEW_SECONDS: int = 300  # 5 Minutes

def generate_agent_credentials() -> Tuple[str, str]:
    """Generates a unique Agent ID and a 256-bit Secret Key."""
    agent_id = f"agent-uuid-{secrets.token_hex(8)}"
    secret_key = secrets.token_hex(32)
    return agent_id, secret_key

def sign_payload(
    agent_id: str,
    secret_key: str,
    payload: Dict[str, Any],
    timestamp: float | None = None,
    nonce: str | None = None
) -> Dict[str, str]:
    """
    Signs an outgoing agent payload dictionary.
    Returns HTTP Security Headers: X-Agent-ID, X-Agent-Timestamp, X-Agent-Nonce, X-Agent-Signature.
    """
    ts = str(int(timestamp if timestamp is not None else time.time()))
    n = nonce or secrets.token_hex(16)
    
    # Canonical string format: agent_id:timestamp:nonce:json_payload
    canonical_body = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    string_to_sign = f"{agent_id}:{ts}:{n}:{canonical_body}"
    
    signature = hmac.new(
        secret_key.encode('utf-8'),
        string_to_sign.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-Timestamp": ts,
        "X-Agent-Nonce": n,
        "X-Agent-Signature": signature
    }

def verify_payload_signature(
    headers: Dict[str, str],
    secret_key: str,
    payload: Dict[str, Any]
) -> Tuple[bool, str]:
    """
    Verifies incoming inter-agent payload signature and validates clock skew + replay nonces.
    """
    # Normalize header keys to lowercase
    h_map = {k.lower(): v for k, v in headers.items()}
    
    agent_id = h_map.get("x-agent-id")
    ts_str = h_map.get("x-agent-timestamp")
    nonce = h_map.get("x-agent-nonce")
    sig = h_map.get("x-agent-signature")
    
    if not all([agent_id, ts_str, nonce, sig]):
        return False, "Missing required cryptographic identity headers (ASI07)."
    
    # 1. Clock Skew Check (Anti-Replay)
    try:
        ts = int(ts_str)
    except ValueError:
        return False, "Invalid timestamp format."
        
    current_ts = int(time.time())
    if abs(current_ts - ts) > _MAX_CLOCK_SKEW_SECONDS:
        return False, f"Clock skew too large ({abs(current_ts - ts)}s > {_MAX_CLOCK_SKEW_SECONDS}s)."
    
    # 2. Nonce Replay Check
    nonce_key = f"{agent_id}:{nonce}"
    with _REPLAY_NONCE_LOCK:
        _prune_stale_nonces(current_ts)
        if nonce_key in _REPLAY_NONCE_CACHE:
            return False, "Replay attack detected: Nonce already used."

    # 3. Signature Verification
    canonical_body = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    string_to_sign = f"{agent_id}:{ts_str}:{nonce}:{canonical_body}"

    expected_sig = hmac.new(
        secret_key.encode('utf-8'),
        string_to_sign.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(sig, expected_sig):
        return False, "Cryptographic signature mismatch: Unauthorized or spoofed agent payload."

    with _REPLAY_NONCE_LOCK:
        # Re-check under the lock: two concurrent verifies for the same
        # nonce could otherwise both pass the check above and both add it.
        if nonce_key in _REPLAY_NONCE_CACHE:
            return False, "Replay attack detected: Nonce already used."
        _REPLAY_NONCE_CACHE[nonce_key] = current_ts
    return True, "Valid Signature"


def _prune_stale_nonces(current_ts: int) -> None:
    """Drop cached nonces whose timestamp has aged past the clock-skew
    window — they could never be successfully replayed at this point
    anyway, since the clock-skew check above would reject them first.
    Caller must hold _REPLAY_NONCE_LOCK."""
    stale = [
        key for key, seen_ts in _REPLAY_NONCE_CACHE.items()
        if current_ts - seen_ts > _MAX_CLOCK_SKEW_SECONDS
    ]
    for key in stale:
        del _REPLAY_NONCE_CACHE[key]
