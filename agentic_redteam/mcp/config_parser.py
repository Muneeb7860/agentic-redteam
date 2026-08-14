"""
agentic_redteam.mcp.config_parser — Multi-Target Desktop MCP Configuration Parser & Dispatcher

Parses Claude Desktop (claude_desktop_config.json), Cursor, and Zed mcpServers definitions,
expands environment variables (${VAR}), enforces timeouts, and audits each server.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from agentic_redteam.mcp.client import StdioMCPClient
from agentic_redteam.mcp.fuzzer import MCPFuzzer


def expand_env_vars(val: Any) -> Any:
    """Recursively expand ${VAR} and $VAR from shell environment."""
    if isinstance(val, str):
        # Match ${VAR} or $VAR
        def _repl(m: re.Match) -> str:
            var_name = m.group(1) or m.group(2)
            return os.environ.get(var_name, "")
        return re.sub(r"\$\{([a-zA-Z_][\w]*)\}|\$([a-zA-Z_][\w]*)", _repl, val)
    elif isinstance(val, dict):
        return {k: expand_env_vars(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [expand_env_vars(x) for x in val]
    return val


class MCPConfigParser:
    """
    Parses MCP server configurations and dispatches automated audits.
    """

    @classmethod
    def load_config(cls, config_path: str | Path) -> Dict[str, Dict[str, Any]]:
        """Loads and normalizes an MCP configuration file."""
        p = Path(config_path)
        if not p.exists():
            raise FileNotFoundError(f"MCP configuration file not found: {p}")

        raw_data = json.loads(p.read_text(encoding="utf-8"))
        servers = raw_data.get("mcpServers", raw_data)
        if not isinstance(servers, dict):
            raise ValueError(f"Invalid MCP configuration: expected 'mcpServers' object, got {type(servers)}")

        normalized: Dict[str, Dict[str, Any]] = {}
        for srv_name, srv_conf in servers.items():
            if not isinstance(srv_conf, dict):
                continue
            cmd = srv_conf.get("command", "")
            args = srv_conf.get("args", [])
            env = srv_conf.get("env", {})
            cwd = srv_conf.get("cwd")

            expanded_args = expand_env_vars(args)
            expanded_env = {k: expand_env_vars(v) for k, v in env.items()}

            full_env = os.environ.copy()
            full_env.update(expanded_env)

            normalized[srv_name] = {
                "command": cmd,
                "args": expanded_args,
                "env": full_env,
                "cwd": cwd,
            }

        return normalized

    @classmethod
    def audit_config(
        cls,
        config_path: str | Path,
        server_filter: Optional[str] = None,
        unsafe_live_fuzzing: bool = False,
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        """
        Audit all (or filtered) MCP servers defined in a configuration file.
        """
        servers = cls.load_config(config_path)
        if server_filter:
            servers = {k: v for k, v in servers.items() if k == server_filter or server_filter in k}

        results: Dict[str, Any] = {}
        for name, conf in servers.items():
            cmd_list = [conf["command"]] + conf["args"]
            try:
                with StdioMCPClient(
                    command=cmd_list,
                    cwd=conf.get("cwd"),
                    env=conf.get("env"),
                    timeout=timeout,
                ) as client:
                    fuzzer = MCPFuzzer(client, unsafe_live_fuzzing=unsafe_live_fuzzing)
                    results[name] = fuzzer.run_full_audit()
            except Exception as e:
                results[name] = {
                    "mcp_passed": False,
                    "pass_rate": 0.0,
                    "error": str(e),
                    "tools_count": 0,
                    "resources_count": 0,
                    "prompts_count": 0,
                    "total_findings": 1,
                    "findings_by_severity": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0},
                    "findings": [{
                        "kind": "transport_spawn_error",
                        "rule_id": "ASI06/MCPProtocolSmuggling",
                        "severity": "CRITICAL",
                        "target": f"server:{name}",
                        "title": "Failed to Spawn or Initialize MCP Server",
                        "detail": f"Subprocess initialization error: {e}",
                        "evidence": str(e),
                        "remediation": "Verify server command and dependencies in mcpServers configuration.",
                    }],
                }

        return {
            "config_path": str(config_path),
            "servers_audited": len(results),
            "results": results,
        }
