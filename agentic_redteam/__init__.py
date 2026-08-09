"""agentic-redteam — Open-source AI Agent Security Scanner.

Free tier: 114 payloads across 8 OWASP-mapped categories.
For advanced features (GART, MARS, registry, reports, trends),
see agentic-redteam-pro: swishos.io/pricing
"""
__version__ = "1.1.0"

from agentic_redteam.fingerprint_test import run_fingerprint_tarpit_exhaustion

__all__ = [
    "run_fingerprint_tarpit_exhaustion",
]
