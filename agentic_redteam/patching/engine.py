"""
agentic_redteam.patching.engine — Virtual Patch Generation Engine

Analyzes audit findings and dynamic tool traces to synthesize active defense rules,
FastAPI/Starlette ASGI middleware, and standalone reverse proxy configurations.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set

from agentic_redteam.scoring import OWASPScore


@dataclass
class PatchRule:
    rule_id: str
    category: str
    target: str  # "ingress" | "egress" | "tool_call"
    action: str  # "block" | "sanitize" | "rate_limit"
    description: str


@dataclass
class PatchConfig:
    version: str = "1.0.0"
    active_categories: List[str] = field(default_factory=list)
    ingress_rules: List[str] = field(default_factory=list)
    egress_rules: List[str] = field(default_factory=list)
    tool_sequence_rules: List[str] = field(default_factory=list)
    money_limit: float = 1000.0
    max_spawn_depth: int = 2
    authorized_tenants: List[str] = field(default_factory=lambda: ["42", "tenant-42", "default"])
    rules: List[PatchRule] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "active_categories": self.active_categories,
            "ingress_rules": self.ingress_rules,
            "egress_rules": self.egress_rules,
            "tool_sequence_rules": self.tool_sequence_rules,
            "money_limit": self.money_limit,
            "max_spawn_depth": self.max_spawn_depth,
            "authorized_tenants": self.authorized_tenants,
            "rules": [asdict(r) for r in self.rules],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class VirtualPatchEngine:
    """
    Synthesizes active defense virtual patches from red-team scan results.
    """

    @classmethod
    def generate_patch_config(
        cls,
        score: OWASPScore | Dict[str, Any],
        trace_findings: Optional[List[Dict[str, Any]]] = None,
        money_limit: float = 1000.0,
        max_spawn_depth: int = 2,
    ) -> PatchConfig:
        """
        Generate a tailored PatchConfig based on observed vulnerabilities.
        """
        failed_cats: Set[str] = set()

        if isinstance(score, OWASPScore):
            for cat, cat_score in score.breakdown.items():
                if cat_score.failed > 0:
                    failed_cats.add(cat)
        elif isinstance(score, dict):
            summary = score.get("summary", score)
            for cat, stats in summary.items():
                if isinstance(stats, dict) and stats.get("failed", 0) > 0:
                    failed_cats.add(cat)

        config = PatchConfig(
            money_limit=money_limit,
            max_spawn_depth=max_spawn_depth,
        )

        # 1. Ingress Rule Mapping
        if "prompt_injection" in failed_cats or "jailbreak" in failed_cats:
            config.ingress_rules.append("prompt_injection")
            config.rules.append(PatchRule(
                rule_id="LLM01/PromptInjection",
                category="prompt_injection",
                target="ingress",
                action="block",
                description="Block incoming prompts matching prompt injection or jailbreak override patterns",
            ))

        if "ssrf" in failed_cats:
            config.ingress_rules.append("ssrf")
            config.rules.append(PatchRule(
                rule_id="LLM07/SSRF",
                category="ssrf",
                target="ingress",
                action="block",
                description="Block requests targeting internal cloud metadata IP addresses or administrative ports",
            ))

        if "autonomous_agent_drift" in failed_cats:
            config.ingress_rules.append("state_tampering")
            config.rules.append(PatchRule(
                rule_id="ASI10/AgentDriftStateTampering",
                category="autonomous_agent_drift",
                target="ingress",
                action="block",
                description="Enforce runtime immutability on system prompts and governance instructions",
            ))

        if "cross_context_retrieval" in failed_cats:
            config.ingress_rules.append("cross_tenant_leak")
            config.rules.append(PatchRule(
                rule_id="LLM02/MultiTenantLeakage",
                category="cross_context_retrieval",
                target="ingress",
                action="block",
                description="Block requests attempting to query vector namespaces outside tenant scope",
            ))

        # 2. Egress Rule Mapping
        if "pii_leakage" in failed_cats:
            config.egress_rules.append("pii_leakage")
            config.rules.append(PatchRule(
                rule_id="LLM06/PIILeakage",
                category="pii_leakage",
                target="egress",
                action="sanitize",
                description="Redact credit card numbers, SSNs, and API keys before sending responses to users",
            ))

        if "code_safety" in failed_cats:
            config.egress_rules.append("code_safety")
            config.rules.append(PatchRule(
                rule_id="LLM04/CodeSafety",
                category="code_safety",
                target="egress",
                action="sanitize",
                description="Mask destructive shell commands (rm -rf, fork bombs) in model outputs",
            ))

        # 3. Dynamic Tool Sequence Rule Mapping
        if "action_level" in failed_cats or "tool_orchestration_abuse" in failed_cats:
            config.tool_sequence_rules.extend(["split_transaction", "subagent_amplification", "state_tampering"])

        if trace_findings:
            for tf in trace_findings:
                kind = tf.get("kind", "")
                if kind and kind not in config.tool_sequence_rules:
                    config.tool_sequence_rules.append(kind)

        # Fallback: if no failures were detected, activate standard baseline defense
        if not config.ingress_rules and not config.egress_rules:
            config.ingress_rules = ["prompt_injection", "ssrf", "state_tampering"]
            config.egress_rules = ["pii_leakage", "code_safety"]
            config.tool_sequence_rules = ["split_transaction", "subagent_amplification"]

        config.active_categories = sorted(list(failed_cats))
        return config

    @classmethod
    def emit_asgi_middleware_code(cls, config: PatchConfig) -> str:
        """
        Generates standalone Python ASGI middleware source code.
        """
        cfg_json = config.to_json(indent=4)
        return f'''"""
Auto-generated Virtual Patch Middleware — agentic-redteam
Generated at: {json.dumps(config.version)}
"""

from agentic_redteam.patching.asgi_middleware import AgenticRedteamMiddleware
from agentic_redteam.patching.engine import PatchConfig

PATCH_CONFIG = PatchConfig(**{cfg_json})


def apply_virtual_patch(app):
    """
    Wrap an existing FastAPI, Starlette, or LiteLLM application with the virtual patch.
    Usage:
        from fastapi import FastAPI
        app = FastAPI()
        app = apply_virtual_patch(app)
    """
    return AgenticRedteamMiddleware(app, config=PATCH_CONFIG)
'''
