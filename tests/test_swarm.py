"""
Unittests for SwishOS Multi-Agent Red-Team Swarm (MARS Mode)
"""

import unittest
from agentic_redteam.swarm import SwarmAttacker

class TestSwarmAttacker(unittest.TestCase):
    def test_swarm_attacker_initialization(self):
        attacker = SwarmAttacker("http://localhost:3000/api/support", max_rounds=2)
        self.assertEqual(attacker.target_url, "http://localhost:3000/api/support")
        self.assertEqual(attacker.max_rounds, 2)

    def test_recon_sub_agent_payload(self):
        attacker = SwarmAttacker("http://localhost:3000/api/support", max_rounds=1)
        recon_res = attacker.run_recon_sub_agent(1)
        self.assertIn("status_code", recon_res)
        self.assertIn("handover_token", recon_res)

if __name__ == '__main__':
    unittest.main()
