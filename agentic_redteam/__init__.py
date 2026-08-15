"""agentic-redteam — Open-source AI Agent Security Scanner.

Free tier: 136 payloads across 12 OWASP-mapped categories, plus tool-sequence
detection and MCP server fuzzing, which are not payload-driven.

For advanced features (GART, MARS, registry, reports, trends),
see agentic-redteam-pro: swishos.io/pricing

The counts above are asserted against the shipped payload files by
tests/test_payloads_canonical.py, so they cannot drift silently the way
they did between 1.0.0 and 1.1.0.
"""
__version__ = "1.1.0"

from agentic_redteam.fingerprint_test import run_fingerprint_tarpit_exhaustion

__all__ = [
    "run_fingerprint_tarpit_exhaustion",
]
