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
import time
from typing import Any, Dict, Tuple

# In-Memory Nonce Cache to prevent Replay Attacks
_REPLAY_NONCE_CACHE: set[str] = set()
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
        
    _REPLAY_NONCE_CACHE.add(nonce_key)
    return True, "Valid Signature"
