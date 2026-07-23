"""
SwishOS Enterprise Zero-Trust Execution Enclave Python SDK (swishos) v0.6.0
Provides Python decorators, client wrappers, and FastAPI middleware for AI Agent pipelines.
"""

import functools
import hashlib
import hmac
import time
from typing import Any, Callable, Dict, Optional
from .exceptions import SwishOSSecurityException


class SwishOSEnclave:
    def __init__(
        self,
        api_key: Optional[str] = None,
        enclave_url: str = "https://swishos.dev/api/support",
        policy: str = "BLOCK_THROW",
        memory_secret: str = "swishos-master-memory-provenance-secret-v1",
    ):
        self.api_key = api_key
        self.enclave_url = enclave_url
        self.policy = policy
        self.memory_secret = memory_secret

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

    def verify_prompt_safety(self, prompt: str) -> Dict[str, Any]:
        prompt_lower = prompt.lower()
        threat_triggers = [
            "ignore previous instructions",
            "system prompt",
            "dan mode",
            "developer mode",
            "sudo mode",
            "override refund policy",
            "bypass security",
        ]
        for trigger in threat_triggers:
            if trigger in prompt_lower:
                proof = self.generate_audit_proof("PROMPT_INJECTION_DETECTED")
                return {
                    "is_safe": False,
                    "matched_rule": "PROMPT_INJECTION_DETECTED",
                    "reason": f"Prompt injection pattern detected: '{trigger}'",
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
                prompt_str = str(kwargs["messages"][-1])

            if prompt_str:
                eval_res = self.verify_prompt_safety(prompt_str)
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


def swishos_guard(policy: str = "BLOCK_THROW") -> Callable:
    enclave = SwishOSEnclave(policy=policy)
    return enclave.guard
