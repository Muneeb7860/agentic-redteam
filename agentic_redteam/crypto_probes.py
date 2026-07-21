"""
SwishOS agentic-redteam Cryptographic Identity Probe Suite
Tests target endpoints for HMAC-SHA256 / Ed25519 signature enforcement, clock skew checks, and nonce replay caching.
"""

from __future__ import annotations
import json
import time
import urllib.request
import urllib.error
from typing import Dict, List, Tuple

from agentic_redteam.crypto import generate_agent_credentials, sign_payload

def run_crypto_probes(target_url: str, timeout: float = 10.0) -> List[Dict[str, str | bool | int]]:
    """
    Executes 4 cryptographic security probes against the target endpoint:
    1. MISSING_HEADERS: Send request with no crypto headers.
    2. FORGED_SIGNATURE: Send request with invalid signature bytes.
    3. CLOCK_SKEW: Send request with timestamp 600 seconds in the past.
    4. REPLAY_NONCE: Send exact same nonce twice to test replay cache.
    """
    agent_id, secret_key = generate_agent_credentials()
    payload = {"query": "Probe cryptographic identity verification."}
    results = []

    # Probe 1: Missing Identity Headers
    p1_res = _send_probe_req(target_url, payload, headers={"Content-Type": "application/json"}, timeout=timeout)
    results.append({
        "probe": "MISSING_HEADERS",
        "description": "Request sent without X-Agent-Signature headers",
        "passed": p1_res.get("status") in ("blocked", "http_error") or p1_res.get("http_code") in (401, 422, 429),
        "response_code": p1_res.get("http_code", 200)
    })

    # Probe 2: Forged Cryptographic Signature
    valid_headers = sign_payload(agent_id, secret_key, payload)
    forged_headers = dict(valid_headers)
    forged_headers["X-Agent-Signature"] = "0000000000000000000000000000000000000000000000000000000000000000"
    p2_res = _send_probe_req(target_url, payload, headers=forged_headers, timeout=timeout)
    results.append({
        "probe": "FORGED_SIGNATURE",
        "description": "Request sent with forged signature digest",
        "passed": p2_res.get("status") in ("blocked", "http_error") or p2_res.get("http_code") in (401, 422, 429),
        "response_code": p2_res.get("http_code", 200)
    })

    # Probe 3: Clock Skew Rejection
    old_ts_headers = sign_payload(agent_id, secret_key, payload, timestamp=time.time() - 600)
    p3_res = _send_probe_req(target_url, payload, headers=old_ts_headers, timeout=timeout)
    results.append({
        "probe": "CLOCK_SKEW",
        "description": "Request sent with timestamp 10 minutes in past",
        "passed": p3_res.get("status") in ("blocked", "http_error") or p3_res.get("http_code") in (401, 422, 429),
        "response_code": p3_res.get("http_code", 200)
    })

    # Probe 4: Anti-Replay Nonce Caching
    nonce_headers = sign_payload(agent_id, secret_key, payload)
    _send_probe_req(target_url, payload, headers=nonce_headers, timeout=timeout)
    p4_res = _send_probe_req(target_url, payload, headers=nonce_headers, timeout=timeout)
    results.append({
        "probe": "REPLAY_NONCE",
        "description": "Request sent twice with exact same cryptographic nonce",
        "passed": p4_res.get("status") in ("blocked", "http_error") or p4_res.get("http_code") in (401, 422, 429),
        "response_code": p4_res.get("http_code", 200)
    })

    return results

def _send_probe_req(url: str, payload: dict, headers: dict, timeout: float = 10.0) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req_headers = {"Content-Type": "application/json", **headers}
    req = urllib.request.Request(url, data=data, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res = json.loads(r.read().decode())
            res["http_code"] = r.status
            return res
    except urllib.error.HTTPError as e:
        try:
            res = json.loads(e.read().decode())
            res["http_code"] = e.code
            return res
        except Exception:
            return {"status": "blocked", "http_code": e.code}
    except Exception as e:
        return {"status": "transport_error", "error": str(e)}
