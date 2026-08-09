"""Free-tier CLI entrypoint for agentic-redteam.

This wraps the full cli.py but gates Pro features with upgrade messages.
The scan engine, scoring, and SARIF export all work — only Pro-exclusive
features (GART, MARS, registry, reports, trends) are blocked.
"""
from __future__ import annotations

import sys


# Pro categories not available in free tier
PRO_CATEGORIES = {
    "indirect_injection", "multi_turn", "centroid_probes",
    "crypto_probes", "asi04_sandbox_escape", "asi10_rogue_persistence",
}

# Pro flags that require a license
PRO_FLAGS = {
    "save", "compare", "app", "register", "report",
    "use_llm_attacker", "swarm", "history", "apps",
}

UPGRADE_MSG = """
⚡ This feature requires agentic-redteam-pro.

   Get a license: https://swishos.io/pricing
   Install:       pip install agentic-redteam-pro
   Docs:          https://swishos.io/developers
"""


def main() -> int:
    """Free-tier entrypoint with Pro gating."""
    # Import the real CLI's parser setup
    from agentic_redteam.cli import main as _original_main

    # Quick pre-check: if any Pro flag is in argv, show upgrade message
    # without importing heavy modules
    argv_set = set(sys.argv[1:])
    for flag in ["--save", "--compare", "--app", "--register", "--report",
                 "--use-llm-attacker", "--swarm", "--history", "--apps"]:
        if flag in argv_set:
            print(f"\n⚡ {flag} requires agentic-redteam-pro.")
            print(UPGRADE_MSG)
            return 0

    # Check if any Pro category is requested
    for arg in sys.argv[1:]:
        if arg in PRO_CATEGORIES:
            print(f"\n⚡ Category '{arg}' requires agentic-redteam-pro.")
            print(UPGRADE_MSG)
            return 0

    # All clear — run the original CLI (which will work because the free
    # categories have payload files and no Pro imports are hit in the
    # execution path for free categories)
    return _original_main()


if __name__ == "__main__":
    sys.exit(main())
