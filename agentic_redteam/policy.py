"""
SwishOS Capability-Based Token & Multi-Day Rolling Spend Policy Engine
Defeats 'Good Child' Sub-Agent Betrayals & 1-Week Slow-Burn Attacks.
"""

from __future__ import annotations
import hmac
import hashlib
import json
import threading
import time
from typing import Any, Dict, List, Tuple

_ROLLING_SPEND_LEDGER: Dict[str, List[Tuple[float, float]]] = {}  # agent_id -> [(timestamp, cost_usd)]
_ROLLING_SPEND_LOCK = threading.Lock()
_MAX_WEEKLY_SPEND_USD = 25.0

def create_capability_token(
    parent_agent_id: str,
    child_agent_id: str,
    allowed_capabilities: List[str],
    secret_key: str,
    ttl_seconds: int = 3600
) -> str:
    """
    Issues a scoped, signed WASI Capability Token for a child sub-agent.
    Prevents parent privilege inheritance and sub-agent betrayal attacks.
    """
    expires_at = int(time.time()) + ttl_seconds
    claim = {
        "parent": parent_agent_id,
        "sub_agent": child_agent_id,
        "capabilities": allowed_capabilities,
        "exp": expires_at
    }
    
    encoded_claim = json.dumps(claim, sort_keys=True, separators=(',', ':'))
    signature = hmac.new(
        secret_key.encode('utf-8'),
        encoded_claim.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return f"{encoded_claim}.{signature}"

def verify_capability_token(
    token: str,
    required_capability: str,
    secret_key: str
) -> Tuple[bool, str]:
    """
    Validates WASI Capability Token expiration, HMAC signature, and capability inclusion.
    """
    if not token or "." not in token:
        return False, "Malformed capability token format."
        
    parts = token.rsplit(".", 1)
    encoded_claim, signature = parts[0], parts[1]
    
    expected_sig = hmac.new(
        secret_key.encode('utf-8'),
        encoded_claim.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected_sig):
        return False, "Capability token signature verification failed."
        
    try:
        claim = json.loads(encoded_claim)
    except Exception:
        return False, "Invalid JSON in capability token."
        
    if time.time() > claim.get("exp", 0):
        return False, "Capability token expired."
        
    allowed = claim.get("capabilities", [])
    if required_capability not in allowed:
        return False, f"Capability '{required_capability}' not granted to sub-agent."
        
    return True, "Authorized"

def record_and_check_rolling_spend(
    agent_id: str,
    cost_usd: float,
    window_days: int = 7,
    max_spend_usd: float = _MAX_WEEKLY_SPEND_USD
) -> Tuple[bool, float, str]:
    """
    Tracks agent spend across a multi-day rolling window to stop 1-week slow-burn attacks.

    SECURITY: this used to read the current ledger, decide pass/fail, and
    append with no locking — two concurrent calls for the same agent_id
    could both read the same pre-append total, both see themselves as
    under the cap, and both get approved, letting combined spend exceed
    max_spend_usd. A module whose stated purpose is defeating slow-burn
    spend attacks shouldn't be bypassable just by making two calls at
    once instead of two calls a week apart. The whole read-prune-check-
    append sequence is now atomic under a lock.
    """
    now = time.time()
    cutoff = now - (window_days * 86400)

    with _ROLLING_SPEND_LOCK:
        # Prune records older than rolling window
        pruned = [
            (ts, cost) for ts, cost in _ROLLING_SPEND_LEDGER.get(agent_id, []) if ts >= cutoff
        ]

        # Calculate cumulative spend
        current_weekly_spend = sum(cost for _, cost in pruned)

        if current_weekly_spend + cost_usd > max_spend_usd:
            if pruned:
                _ROLLING_SPEND_LEDGER[agent_id] = pruned
            else:
                # Nothing left after pruning and this call didn't add
                # anything either — drop the key instead of leaving an
                # empty list around forever. (Note: this doesn't bound
                # ledger size against an attacker who supplies a fresh
                # agent_id on every call within the window — agent_id is
                # assumed to be an authenticated identity, not
                # attacker-controlled free text; enforce that at the
                # caller.)
                _ROLLING_SPEND_LEDGER.pop(agent_id, None)
            return False, current_weekly_spend, f"Rolling {window_days}-day spend cap ${max_spend_usd:.2f} exceeded (Current: ${current_weekly_spend:.2f})."

        pruned.append((now, cost_usd))
        _ROLLING_SPEND_LEDGER[agent_id] = pruned
        return True, current_weekly_spend + cost_usd, "Spend approved"
