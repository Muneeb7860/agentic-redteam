"""
agentic_redteam.patching.asgi_middleware — Fast, Zero-Dependency ASGI Defensive Middleware

Drop-in protection for FastAPI, Starlette, LiteLLM, and any ASGI Python application.
Filters malicious ingress prompts, sanitizes egress PII/secrets, and enforces sequence limits.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Set

from agentic_redteam.patching.engine import PatchConfig
from agentic_redteam.patching.guardrails import (
    ToolCallGuard,
    check_ingress,
    sanitize_egress,
)


class AgenticRedteamMiddleware:
    """
    ASGI Middleware that intercepts, inspects, and patches traffic in real time.
    """

    def __init__(
        self,
        app: Any,
        config: Optional[PatchConfig] = None,
        tool_guard: Optional[ToolCallGuard] = None,
    ):
        self.app = app
        self.config = config or PatchConfig()
        self.tool_guard = tool_guard or ToolCallGuard(
            money_limit=self.config.money_limit,
            max_spawn_depth=self.config.max_spawn_depth,
        )

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Buffer request body
        body_chunks: List[bytes] = []
        more_body = True
        while more_body:
            message = await receive()
            body_chunks.append(message.get("body", b""))
            more_body = message.get("more_body", False)

        raw_body = b"".join(body_chunks)
        body_text = raw_body.decode("utf-8", errors="ignore")

        # Ingress Inspection
        session_id = self._extract_session_id(scope, body_text)
        is_blocked, rule_id, reason = check_ingress(
            body_text,
            rules=set(self.config.ingress_rules),
            authorized_tenants=tuple(self.config.authorized_tenants),
        )

        if is_blocked:
            await self._send_blocked_response(send, rule_id or "SECURITY_BLOCK", reason or "Security policy violation")
            return

        # Re-queue received body for downstream app
        async def mock_receive() -> Dict[str, Any]:
            return {"type": "http.request", "body": raw_body, "more_body": False}

        # Intercept and sanitize egress response
        response_status = 200
        response_headers: List[Tuple[bytes, bytes]] = []
        response_chunks: List[bytes] = []

        async def intercept_send(message: Dict[str, Any]) -> None:
            nonlocal response_status, response_headers, response_chunks
            msg_type = message.get("type")

            if msg_type == "http.response.start":
                response_status = message.get("status", 200)
                response_headers = list(message.get("headers", []))
            elif msg_type == "http.response.body":
                response_chunks.append(message.get("body", b""))
                if not message.get("more_body", False):
                    # Process full response
                    full_resp = b"".join(response_chunks).decode("utf-8", errors="ignore")
                    sanitized_resp, _ = sanitize_egress(full_resp, rules=set(self.config.egress_rules))
                    out_bytes = sanitized_resp.encode("utf-8")

                    # Update Content-Length header
                    new_headers = [
                        (k, v) for k, v in response_headers
                        if k.lower() != b"content-length"
                    ]
                    new_headers.append((b"content-length", str(len(out_bytes)).encode("ascii")))

                    await send({"type": "http.response.start", "status": response_status, "headers": new_headers})
                    await send({"type": "http.response.body", "body": out_bytes, "more_body": False})

        await self.app(scope, mock_receive, intercept_send)

    def _extract_session_id(self, scope: Dict[str, Any], body_text: str) -> str:
        headers = dict(scope.get("headers", []))
        session_id = headers.get(b"x-session-id", b"").decode("ascii", errors="ignore")
        if not session_id:
            try:
                data = json.loads(body_text)
                if isinstance(data, dict):
                    session_id = str(data.get("session_id") or data.get("user_id") or "default_session")
            except Exception:
                session_id = "default_session"
        return session_id or "default_session"

    async def _send_blocked_response(self, send: Callable, rule_id: str, reason: str) -> None:
        payload = json.dumps({
            "status": "blocked",
            "message": f"Request blocked by virtual patch ({rule_id})",
            "rule": rule_id,
            "reason": reason,
        }).encode("utf-8")

        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode("ascii")),
            (b"x-virtual-patch", b"agentic-redteam-v1"),
        ]

        await send({"type": "http.response.start", "status": 403, "headers": headers})
        await send({"type": "http.response.body", "body": payload, "more_body": False})
