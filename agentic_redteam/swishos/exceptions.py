"""
SwishOS Python SDK Exceptions
"""

class SwishOSSecurityException(Exception):
    """
    Raised when an autonomous agent prompt or tool call violates enclave zero-trust policy.
    """

    def __init__(self, reason: str, rule_triggered: str, audit_proof: str, nonce: str, timestamp: str):
        super().__init__(f"SwishOS Security Block: {reason} (Rule: {rule_triggered})")
        self.reason = reason
        self.rule_triggered = rule_triggered
        self.audit_proof = audit_proof
        self.nonce = nonce
        self.timestamp = timestamp
