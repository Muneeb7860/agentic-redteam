"""
agentic_redteam.patching — Active Defense Virtual Patching Package

Provides dynamic virtual patching, ASGI defensive middleware, standalone reverse proxy,
and deterministic ingress/egress/sequence guardrails.
"""

from agentic_redteam.patching.asgi_middleware import AgenticRedteamMiddleware
from agentic_redteam.patching.engine import PatchConfig, PatchRule, VirtualPatchEngine
from agentic_redteam.patching.guardrails import (
    ToolCallGuard,
    check_ingress,
    sanitize_egress,
)
from agentic_redteam.patching.reverse_proxy import AgenticPatchProxy, run_proxy

__all__ = [
    "VirtualPatchEngine",
    "PatchConfig",
    "PatchRule",
    "AgenticRedteamMiddleware",
    "AgenticPatchProxy",
    "run_proxy",
    "ToolCallGuard",
    "check_ingress",
    "sanitize_egress",
]
