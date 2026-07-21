"""
Unit tests for Zero-Trust Identity, Capability Policy, and Sandbox Physics Modules.
"""

import unittest
import time
from agentic_redteam.crypto import (
    generate_agent_credentials,
    sign_payload,
    verify_payload_signature
)
from agentic_redteam.policy import (
    create_capability_token,
    verify_capability_token,
    record_and_check_rolling_spend
)
from agentic_redteam.sandbox_config import (
    generate_gvisor_docker_compose_service,
    generate_iptables_metadata_drop_commands
)


class TestZeroTrustModules(unittest.TestCase):

    def test_crypto_identity_signing(self):
        agent_id, secret_key = generate_agent_credentials()
        payload = {"query": "Execute task #104", "amount": 25.50}

        headers = sign_payload(agent_id, secret_key, payload)
        self.assertIn("X-Agent-ID", headers)
        self.assertIn("X-Agent-Signature", headers)

        # 1. Valid signature
        valid, msg = verify_payload_signature(headers, secret_key, payload)
        self.assertTrue(valid, f"Verification failed: {msg}")

        # 2. Tampered signature check (fresh headers with modified payload)
        headers_tampered = sign_payload(agent_id, secret_key, payload)
        tampered_payload = {"query": "Execute task #104", "amount": 999999.00}
        valid_tampered, msg_tampered = verify_payload_signature(headers_tampered, secret_key, tampered_payload)
        self.assertFalse(valid_tampered)
        self.assertIn("mismatch", msg_tampered.lower())

    def test_wasi_capability_policy(self):
        parent_id = "agent-parent-1"
        child_id = "agent-child-9"
        secret_key = "super-secret-key"

        # Issue token with summarize_text capability ONLY
        token = create_capability_token(parent_id, child_id, ["summarize_text"], secret_key)

        # Authorized capability check
        ok, msg = verify_capability_token(token, "summarize_text", secret_key)
        self.assertTrue(ok)

        # Unauthorized capability check (Sub-Agent Betrayal Attempt)
        unauthorized_ok, msg_unauth = verify_capability_token(token, "read_database", secret_key)
        self.assertFalse(unauthorized_ok)
        self.assertIn("not granted", msg_unauth)

    def test_rolling_spend_ledger(self):
        agent_id = "agent-slow-burn"
        # Day 1: $10 spend
        ok1, total1, _ = record_and_check_rolling_spend(agent_id, 10.0, max_spend_usd=25.0)
        self.assertTrue(ok1)
        self.assertEqual(total1, 10.0)

        # Day 3: $10 spend (Cumulative $20)
        ok2, total2, _ = record_and_check_rolling_spend(agent_id, 10.0, max_spend_usd=25.0)
        self.assertTrue(ok2)
        self.assertEqual(total2, 20.0)

        # Day 7: $10 spend (Cumulative $30 -> Exceeds $25 Cap)
        ok3, total3, msg3 = record_and_check_rolling_spend(agent_id, 10.0, max_spend_usd=25.0)
        self.assertFalse(ok3)
        self.assertIn("exceeded", msg3.lower())

    def test_sandbox_manifest_generator(self):
        manifest = generate_gvisor_docker_compose_service("my-agent", memory_limit_mb=512)
        service = manifest["my-agent"]
        self.assertEqual(service["runtime"], "runsc")
        self.assertTrue(service["read_only"])
        self.assertIn("/tmp:rw,noexec,nosuid,size=64m", service["tmpfs"])

        iptables_rules = generate_iptables_metadata_drop_commands()
        self.assertTrue(any("169.254.169.254" in r for r in iptables_rules))


if __name__ == "__main__":
    unittest.main()
