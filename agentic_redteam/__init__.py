"""
SwishOS agentic-redteam v0.5.0 Enterprise SDK
Frontier-Grade AI Agent Red-Teaming & Security Benchmark Harness
"""

from agentic_redteam.crypto import generate_agent_credentials, sign_payload, verify_payload_signature
from agentic_redteam.policy import create_capability_token, verify_capability_token
from agentic_redteam.crypto_probes import run_crypto_probes
from agentic_redteam.telemetry_verifier import verify_audit_proof_header
from agentic_redteam.fingerprint_test import test_fingerprint_tarpit_exhaustion
from agentic_redteam.mutators import apply_mutations
from agentic_redteam.gart_attacker import GenerativeAttacker

__version__ = "0.5.0"
__all__ = [
    "generate_agent_credentials",
    "sign_payload",
    "verify_payload_signature",
    "create_capability_token",
    "verify_capability_token",
    "run_crypto_probes",
    "verify_audit_proof_header",
    "test_fingerprint_tarpit_exhaustion",
    "apply_mutations",
    "GenerativeAttacker",
]
