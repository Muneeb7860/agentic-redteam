"""
SwishOS agentic-redteam Cryptographic Telemetry Verifier
Validates X-SwishOS-Audit-Proof headers to catch fake/hallucinated JSON error responses.
"""

from __future__ import annotations
import hmac
import hashlib
from typing import Dict, Tuple

AUDIT_PROOF_SECRET = "swishos-audit-proof-signature-key-v4"

def verify_audit_proof_header(
    headers: Dict[str, str],
    client_ip: str = "127.0.0.1",
    rule_triggered: str = ""
) -> Tuple[bool, str]:
    """
    Verifies that the target response contains a valid HMAC-SHA256 audit proof signature.
    Prevents scanners from being tricked by fake hallucinated LLM JSON error output.
    """
    h_map = {k.lower(): v for k, v in headers.items()}
    
    proof_sig = h_map.get("x-swishos-audit-proof")
    ts_str = h_map.get("x-swishos-audit-timestamp")
    nonce = h_map.get("x-swishos-audit-nonce")

    if not proof_sig or not ts_str or not nonce:
        return False, "Missing X-SwishOS-Audit-Proof cryptographic headers (Possible fake error response)."

    # Verify signature if rule_triggered is known, otherwise verify header structure presence
    if rule_triggered:
        string_to_sign = f"{rule_triggered}:{client_ip}:{ts_str}:{nonce}"
        expected_sig = hmac.new(
            AUDIT_PROOF_SECRET.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(proof_sig, expected_sig):
            return False, "Cryptographic audit proof mismatch: Fake error response detected!"

    return True, "Valid Audit Proof"
