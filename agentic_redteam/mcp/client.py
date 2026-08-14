"""
agentic_redteam.mcp.client — Resilient JSON-RPC 2.0 Clients for Local STDIO & Remote SSE MCP Servers

Implements:
1. StdioMCPClient: Spawns local subprocesses with non-blocking threaded I/O
   (preventing OS pipe buffer deadlocks), stdout log noise filtering,
   and complete 3-step MCP handshake (initialize -> initialized).
2. SSEMCPClient: Connects to remote SSE endpoints, handles multiline data frames
   and keepalives, extracts session endpoints, and routes POST messages.
"""

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional, Tuple


class MCPTransportError(Exception):
    """Raised when transport communication fails or encounters unrecoverable I/O errors."""
    pass


class MCPClient(ABC):
    """Abstract base class for Model Context Protocol clients."""

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._request_id: int = 0
        self._initialized: bool = False
        self.server_info: Dict[str, Any] = {}
        self.server_capabilities: Dict[str, Any] = {}
        self.notification_handlers: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
        self.sampling_handler: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def on_notification(self, method: str, handler: Callable[[Dict[str, Any]], None]) -> None:
        """Register a callback for an inbound server notification."""
        self.notification_handlers.setdefault(method, []).append(handler)

    @abstractmethod
    def start(self) -> None:
        """Start the transport and connect to the server."""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop the transport and clean up resources."""
        pass

    @abstractmethod
    def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send a JSON-RPC 2.0 request and wait for the response."""
        pass

    @abstractmethod
    def send_notification(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        """Send a JSON-RPC 2.0 notification (no response expected)."""
        pass

    def initialize(self, advertise_sampling: bool = True) -> Dict[str, Any]:
        """
        Execute full 3-step MCP handshake:
        1. Client sends 'initialize' request
        2. Server returns capabilities and info
        3. Client sends 'notifications/initialized' notification
        """
        client_capabilities: Dict[str, Any] = {
            "roots": {"listChanged": True},
        }
        if advertise_sampling:
            client_capabilities["sampling"] = {}

        params = {
            "protocolVersion": "2024-11-05",
            "capabilities": client_capabilities,
            "clientInfo": {
                "name": "agentic-redteam-fuzzer",
                "version": "1.0.0",
            },
        }

        resp = self.send_request("initialize", params)
        if "error" in resp:
            raise MCPTransportError(f"MCP initialize failed: {resp['error']}")

        result = resp.get("result", {})
        self.server_info = result.get("serverInfo", {})
        self.server_capabilities = result.get("capabilities", {})
        self._initialized = True

        # Step 3: Send initialized notification
        self.send_notification("notifications/initialized", {})
        return result

    def __enter__(self) -> MCPClient:
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()


class StdioMCPClient(MCPClient):
    """
    Subprocess STDIO transport for MCP servers.
    Uses separate reader threads for stdout and stderr to prevent 64 KB pipe buffer deadlocks,
    and isolates JSON-RPC lines from debug log noise.
    """

    def __init__(
        self,
        command: str | List[str],
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
    ):
        super().__init__(timeout=timeout)
        self.raw_command = command
        self.cwd = cwd or os.getcwd()
        self.env = env or os.environ.copy()
        self.process: Optional[subprocess.Popen] = None
        self._stdout_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._response_queues: Dict[int, queue.Queue] = {}
        self._lock = threading.Lock()
        self._running = False
        self.stderr_logs: List[str] = []
        self.crashed: bool = False
        self.exit_code: Optional[int] = None

    def _resolve_binary(self, cmd_list: List[str]) -> List[str]:
        if not cmd_list:
            return cmd_list
        bin_name = cmd_list[0]
        resolved = shutil.which(bin_name)
        if resolved:
            cmd_list[0] = resolved
        elif sys.platform == "win32" and not bin_name.lower().endswith(".cmd") and not bin_name.lower().endswith(".exe"):
            for ext in (".cmd", ".exe", ".bat"):
                cand = shutil.which(bin_name + ext)
                if cand:
                    cmd_list[0] = cand
                    break
        return cmd_list

    def start(self) -> None:
        if isinstance(self.raw_command, str):
            # Split with shell semantics if string
            import shlex
            cmd_list = shlex.split(self.raw_command, posix=(sys.platform != "win32"))
        else:
            cmd_list = list(self.raw_command)

        cmd_list = self._resolve_binary(cmd_list)

        try:
            self.process = subprocess.Popen(
                cmd_list,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.cwd,
                env=self.env,
                bufsize=0,  # Unbuffered binary/text streams
            )
        except Exception as e:
            raise MCPTransportError(f"Failed to spawn MCP server process {cmd_list}: {e}")

        self._running = True

        # Start stdout reader thread
        self._stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._stdout_thread.start()

        # Start stderr reader thread
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stderr_thread.start()

    def _read_stdout(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        while self._running:
            try:
                line_bytes = self.process.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue

                # Filter out non-JSON lines (e.g. stdout debug logs)
                if not line.startswith("{") or not line.endswith("}"):
                    continue

                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if not isinstance(msg, dict):
                    continue

                # Check if it's a response to a pending request
                msg_id = msg.get("id")
                if msg_id is not None and isinstance(msg_id, int):
                    with self._lock:
                        q = self._response_queues.get(msg_id)
                    if q:
                        q.put(msg)
                        continue

                # Check if it's a server-initiated request (e.g. sampling/createMessage or roots/list)
                if "method" in msg and "id" in msg:
                    method = msg["method"]
                    if method == "sampling/createMessage" and self.sampling_handler:
                        resp_data = self.sampling_handler(msg.get("params", {}))
                        self._send_raw({
                            "jsonrpc": "2.0",
                            "id": msg["id"],
                            "result": resp_data,
                        })
                    else:
                        # Handle via notification or default empty
                        pass
                    continue

                # Check if it's a notification
                if "method" in msg and "id" not in msg:
                    method = msg["method"]
                    handlers = self.notification_handlers.get(method, [])
                    for h in handlers:
                        try:
                            h(msg.get("params", {}))
                        except Exception:
                            pass
            except Exception:
                break

    def _read_stderr(self) -> None:
        assert self.process is not None and self.process.stderr is not None
        while self._running:
            try:
                line_bytes = self.process.stderr.readline()
                if not line_bytes:
                    break
                err_line = line_bytes.decode("utf-8", errors="ignore").rstrip()
                if err_line:
                    self.stderr_logs.append(err_line)
            except Exception:
                break

    def _send_raw(self, payload: Dict[str, Any]) -> None:
        if not self.process or self.process.poll() is not None:
            self.crashed = True
            self.exit_code = self.process.poll() if self.process else -1
            raise MCPTransportError(f"MCP server process terminated unexpectedly (exit code {self.exit_code})")

        data = (json.dumps(payload) + "\n").encode("utf-8")
        try:
            assert self.process.stdin is not None
            self.process.stdin.write(data)
            self.process.stdin.flush()
        except Exception as e:
            self.crashed = True
            self.exit_code = self.process.poll() if self.process else -1
            raise MCPTransportError(f"Failed writing to MCP process stdin: {e}")

    def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        req_id = self._next_id()
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params or {},
        }
        resp_q: queue.Queue = queue.Queue()
        with self._lock:
            self._response_queues[req_id] = resp_q

        try:
            self._send_raw(payload)
            resp = resp_q.get(timeout=self.timeout)
            return resp
        except queue.Empty:
            # Check if process died during execution
            if self.process and self.process.poll() is not None:
                self.crashed = True
                self.exit_code = self.process.poll()
                raise MCPTransportError(f"MCP server crashed during '{method}' (exit code {self.exit_code})")
            raise MCPTransportError(f"Timeout ({self.timeout}s) waiting for response to '{method}' (id={req_id})")
        finally:
            with self._lock:
                self._response_queues.pop(req_id, None)

    def send_notification(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        self._send_raw(payload)

    def stop(self) -> None:
        self._running = False
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=2.0)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
        self.process = None


class SSEMCPClient(MCPClient):
    """
    Remote Network SSE transport for MCP servers.
    Connects to SSE endpoint, captures session endpoint URI,
    and sends JSON-RPC requests via HTTP POST.
    """

    def __init__(self, sse_url: str, timeout: float = 30.0):
        super().__init__(timeout=timeout)
        self.sse_url = sse_url
        self.session_post_url: Optional[str] = None
        self._running = False
        self._sse_thread: Optional[threading.Thread] = None
        self._response_queues: Dict[int, queue.Queue] = {}
        self._lock = threading.Lock()

    def start(self) -> None:
        self._running = True
        endpoint_ready = threading.Event()

        def _sse_listener():
            req = urllib.request.Request(self.sse_url, headers={"Accept": "text/event-stream"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    buffer = ""
                    event_name = "message"
                    for raw_line in resp:
                        if not self._running:
                            break
                        line = raw_line.decode("utf-8", errors="ignore").rstrip("\r\n")

                        # Handle keepalive/comment
                        if line.startswith(":"):
                            continue

                        if line.startswith("event:"):
                            event_name = line[6:].strip()
                        elif line.startswith("data:"):
                            data_chunk = line[5:].strip()
                            buffer += data_chunk + "\n"
                        elif not line:
                            # End of SSE event frame
                            if event_name == "endpoint":
                                raw_endpoint = buffer.strip()
                                if raw_endpoint.startswith("http"):
                                    self.session_post_url = raw_endpoint
                                else:
                                    from urllib.parse import urljoin
                                    self.session_post_url = urljoin(self.sse_url, raw_endpoint)
                                endpoint_ready.set()
                            elif buffer.strip():
                                try:
                                    msg = json.loads(buffer.strip())
                                    if isinstance(msg, dict) and "id" in msg:
                                        with self._lock:
                                            q = self._response_queues.get(msg["id"])
                                        if q:
                                            q.put(msg)
                                except Exception:
                                    pass
                            buffer = ""
                            event_name = "message"
            except Exception as e:
                endpoint_ready.set()

        self._sse_thread = threading.Thread(target=_sse_listener, daemon=True)
        self._sse_thread.start()

        if not endpoint_ready.wait(timeout=self.timeout) or not self.session_post_url:
            raise MCPTransportError(f"Failed to connect to MCP SSE stream or obtain session endpoint from {self.sse_url}")

    def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.session_post_url:
            raise MCPTransportError("SSE transport is not connected")

        req_id = self._next_id()
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params or {},
        }
        resp_q: queue.Queue = queue.Queue()
        with self._lock:
            self._response_queues[req_id] = resp_q

        try:
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.session_post_url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_text = resp.read().decode("utf-8", errors="ignore").strip()
                if resp_text:
                    try:
                        direct_json = json.loads(resp_text)
                        if isinstance(direct_json, dict) and direct_json.get("id") == req_id:
                            return direct_json
                    except Exception:
                        pass

            # Wait for response over SSE event stream
            return resp_q.get(timeout=self.timeout)
        except queue.Empty:
            raise MCPTransportError(f"Timeout ({self.timeout}s) waiting for SSE response to '{method}' (id={req_id})")
        finally:
            with self._lock:
                self._response_queues.pop(req_id, None)

    def send_notification(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        if not self.session_post_url:
            return
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.session_post_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout):
                pass
        except Exception:
            pass

    def stop(self) -> None:
        self._running = False
        self.session_post_url = None
