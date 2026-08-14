"""
agentic_redteam.patching.reverse_proxy — Standalone Zero-Dependency Defensive Reverse Proxy

Sits in front of any black-box LLM service or agent endpoint.
Enforces real-time ingress defense, sequence tracking, and egress sanitization.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional

from agentic_redteam.patching.engine import PatchConfig
from agentic_redteam.patching.guardrails import (
    ToolCallGuard,
    check_ingress,
    sanitize_egress,
)


class PatchProxyHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler that inspects and protects upstream traffic.
    """

    target_url: str = "http://localhost:8000"
    patch_config: PatchConfig = PatchConfig()
    tool_guard: ToolCallGuard = ToolCallGuard()

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length)
        body_text = raw_body.decode("utf-8", errors="ignore")

        # 1. Ingress Inspection
        is_blocked, rule_id, reason = check_ingress(
            body_text,
            rules=set(self.patch_config.ingress_rules),
            authorized_tenants=tuple(self.patch_config.authorized_tenants),
        )

        if is_blocked:
            self._send_blocked(rule_id or "SECURITY_BLOCK", reason or "Security policy violation")
            return

        # 2. Forward to Upstream Target
        target_endpoint = self.target_url
        req_headers = {"Content-Type": self.headers.get("Content-Type", "application/json")}
        req = urllib.request.Request(target_endpoint, data=raw_body, headers=req_headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=60.0) as resp:
                resp_status = resp.status
                resp_raw = resp.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            resp_status = e.code
            resp_raw = e.read().decode("utf-8", errors="ignore")
        except Exception as e:
            self._send_json(502, {"status": "error", "message": f"Upstream proxy error: {e}"})
            return

        # 3. Egress Sanitization
        sanitized_resp, _ = sanitize_egress(resp_raw, rules=set(self.patch_config.egress_rules))
        self._send_json(resp_status, sanitized_resp, is_raw_json=True)

    def do_GET(self) -> None:
        if self.path == "/healthz" or self.path == "/health":
            self._send_json(200, {"status": "healthy", "service": "agentic-redteam-virtual-patch-proxy"})
            return
        self._send_json(405, {"status": "error", "message": "Method not allowed"})

    def _send_blocked(self, rule_id: str, reason: str) -> None:
        payload = {
            "status": "blocked",
            "message": f"Request blocked by virtual patch ({rule_id})",
            "rule": rule_id,
            "reason": reason,
        }
        self._send_json(403, payload)

    def _send_json(self, status: int, data: Any, is_raw_json: bool = False) -> None:
        if is_raw_json and isinstance(data, str):
            out_bytes = data.encode("utf-8")
        else:
            out_bytes = json.dumps(data, indent=2).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out_bytes)))
        self.send_header("X-Virtual-Patch", "agentic-redteam-v1")
        self.end_headers()
        self.wfile.write(out_bytes)

    def log_message(self, format: str, *args: Any) -> None:
        # Silence standard HTTP access logging during proxy tests
        pass


class AgenticPatchProxy:
    """
    Manages the lifecycle of a standalone virtual patch reverse proxy server.
    """

    def __init__(
        self,
        target_url: str,
        port: int = 8080,
        host: str = "0.0.0.0",
        config: Optional[PatchConfig] = None,
    ):
        self.target_url = target_url
        self.port = port
        self.host = host
        self.config = config or PatchConfig()
        self.server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, block: bool = False) -> None:
        """Starts the reverse proxy server."""
        PatchProxyHandler.target_url = self.target_url
        PatchProxyHandler.patch_config = self.config
        PatchProxyHandler.tool_guard = ToolCallGuard(
            money_limit=self.config.money_limit,
            max_spawn_depth=self.config.max_spawn_depth,
        )

        self.server = HTTPServer((self.host, self.port), PatchProxyHandler)
        if block:
            print(f"🛡️  Agentic Red-Team Virtual Patch Proxy listening on {self.host}:{self.port} -> {self.target_url}")
            try:
                self.server.serve_forever()
            except KeyboardInterrupt:
                self.stop()
        else:
            self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Stops the reverse proxy server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


def run_proxy(
    target_url: str,
    port: int = 8080,
    host: str = "0.0.0.0",
    config: Optional[PatchConfig] = None,
    block: bool = True,
) -> AgenticPatchProxy:
    """Convenience helper to boot and run the standalone virtual patch reverse proxy."""
    proxy = AgenticPatchProxy(target_url=target_url, port=port, host=host, config=config)
    proxy.start(block=block)
    return proxy
