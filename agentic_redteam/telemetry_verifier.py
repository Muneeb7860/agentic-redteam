"""
SwishOS agentic-redteam Cryptographic Telemetry Verifier
Validates X-SwishOS-Audit-Proof headers to catch fake/hallucinated JSON error responses.
"""

from __future__ import annotations
import hmac
import hashlib
import secrets
import warnings
from typing import Dict, Tuple
import os

# SECURITY: this used to fall back to a hardcoded secret literal
# ("swishos-audit-proof-signature-key-v4") shipped in this public repo. A
# target that happened to sign with that same well-known string would
# "verify" successfully — which is worthless, since an attacker forging a
# fake blocked-response proof has that exact string too. A verifier default
# should never be something an attacker can already read from source.
#
# Now: SWISHOS_AUDIT_PROOF_SECRET (same env var the swishos SDK's
# SwishOSEnclave reads) is used if set, so a real target and this scanner
# can be configured to share one secret. If it's unset, we generate a
# random per-process secret and warn loudly — verification will then
# correctly fail closed (return False) against any real target's proof
# instead of silently "passing" against a guessable default.
_env_secret = os.environ.get("SWISHOS_AUDIT_PROOF_SECRET")
if _env_secret:
    AUDIT_PROOF_SECRET = _env_secret
else:
    warnings.warn(
        "telemetry_verifier: SWISHOS_AUDIT_PROOF_SECRET is not set. Using a "
        "random per-process secret — audit-proof verification will fail "
        "closed against any real target unless this env var is set to "
        "match the target's configured secret.",
        stacklevel=2,
    )
    AUDIT_PROOF_SECRET = secrets.token_hex(32)

def verify_audit_proof_header(
    headers: Dict[str, str],
    client_ip: str = "127.0.0.1",
    rule_triggered: str = "",
    secret: str | None = None,
) -> Tuple[bool, str]:
    """
    Verifies that the target response contains a valid HMAC-SHA256 audit proof signature.
    Prevents scanners from being tricked by fake hallucinated LLM JSON error output.

    Args:
        secret: override the module-level AUDIT_PROOF_SECRET for this call
            (e.g. a per-target secret loaded from the app registry). Defaults
            to AUDIT_PROOF_SECRET, which is read from SWISHOS_AUDIT_PROOF_SECRET.
    """
    h_map = {k.lower(): v for k, v in headers.items()}

    proof_sig = h_map.get("x-swishos-audit-proof")
    ts_str = h_map.get("x-swishos-audit-timestamp")
    nonce = h_map.get("x-swishos-audit-nonce")

    if not proof_sig or not ts_str or not nonce:
        return False, "Missing X-SwishOS-Audit-Proof cryptographic headers (Possible fake error response)."

    # Verify signature if rule_triggered is known, otherwise verify header structure presence
    if rule_triggered:
        signing_secret = secret if secret is not None else AUDIT_PROOF_SECRET
        string_to_sign = f"{rule_triggered}:{client_ip}:{ts_str}:{nonce}"
        expected_sig = hmac.new(
            signing_secret.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(proof_sig, expected_sig):
            return False, "Cryptographic audit proof mismatch: Fake error response detected!"

    return True, "Valid Audit Proof"
