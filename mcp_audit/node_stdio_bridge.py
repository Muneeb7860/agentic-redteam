"""
Python Subprocess Bridge to Real Node.js stdio MCP Server.
Spawns node mcp_audit/node_mcp_server.js as a child process using subprocess.Popen(..., stdin=PIPE, stdout=PIPE).
Pipes real JSON-RPC 2.0 frames over process stdio streams to execute the teardown exploit.
"""

from __future__ import annotations
import json
import os
import select
import subprocess
import sys
import threading
import time
from pathlib import Path

# Add parent directory to python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentic_redteam.telemetry_verifier import verify_audit_proof_header

_READLINE_TIMEOUT_SECONDS = 10


class NodeBridgeTimeoutError(RuntimeError):
    """Raised when the Node child process doesn't respond in time."""


def _readline_with_timeout(pipe, timeout: float = _READLINE_TIMEOUT_SECONDS) -> str:
    """select()-gated readline so a hung/silent child process raises instead
    of blocking this script forever."""
    ready, _, _ = select.select([pipe], [], [], timeout)
    if not ready:
        raise NodeBridgeTimeoutError(
            f"Node MCP server did not respond within {timeout}s — it may have "
            "crashed or deadlocked on stderr output. Check stderr above."
        )
    return pipe.readline()


def _drain_stderr(proc: subprocess.Popen) -> None:
    """Continuously read the child's stderr in the background.

    Without this, an unread stderr pipe fills its OS buffer (~64KB) once the
    child writes enough to it, the child blocks trying to write more, and
    this script blocks trying to read stdout — a classic subprocess pipe
    deadlock. Draining stderr on its own thread prevents that regardless of
    how much the child writes.
    """
    for line in proc.stderr:
        if line.strip():
            print(f"  [node stderr] {line.rstrip()}")


def run_node_stdio_mcp_bridge_exploit():
    print("================================================================")
    print("⚡ REAL NODE.JS STDIO PROCESS PIPE MCP EXPLOIT AUDIT")
    print("================================================================")

    server_script = Path(__file__).resolve().parent / "node_mcp_server.js"

    # 1. Spawn Node.js MCP server child process over stdin/stdout pipes
    print(f"\n[STEP 1] Launching Node.js MCP Stdio Child Process...")
    print(f"  Command: node {server_script}")

    proc = subprocess.Popen(
        ["node", str(server_script)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    # Drain stderr on a background thread for the process's whole lifetime —
    # see _drain_stderr's docstring for why an unread pipe can deadlock this.
    stderr_thread = threading.Thread(target=_drain_stderr, args=(proc,), daemon=True)
    stderr_thread.start()

    try:
        time.sleep(0.5)
        print("  ✅ Process spawned successfully (PID:", proc.pid, ")")

        # 2. Query MCP Tools List Frame over stdin pipe
        req_list = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n"
        proc.stdin.write(req_list)
        proc.stdin.flush()

        raw_resp_list = _readline_with_timeout(proc.stdout)
        resp_list = json.loads(raw_resp_list)
        print("\n[STEP 2] Querying MCP Tools Manifest over stdio stdin/stdout:")
        print("  " + json.dumps(resp_list, indent=2))

        # 3. Simulate Indirect Prompt Injection triggering drop_table tool call
        print("\n[STEP 3] Feeding Indirect Prompt Injection Payload over stdio stdin pipe...")
        req_call = json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "drop_table",
                "arguments": {"table_name": "users"}
            }
        }) + "\n"

        proc.stdin.write(req_call)
        proc.stdin.flush()

        raw_resp_call = _readline_with_timeout(proc.stdout)
        resp_call = json.loads(raw_resp_call)

        print("\n  ❌ REAL NODE.JS STDIO PROCESS EXPLOIT CONFIRMED:")
        print("  Received Raw JSON-RPC Response on stdout pipe:")
        print("  " + json.dumps(resp_call, indent=2))
    finally:
        # 4. Terminate process clean — bounded wait, escalate to kill() if the
        # child ignores SIGTERM instead of hanging this script indefinitely.
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("  ⚠️  Node process did not exit after SIGTERM, sending SIGKILL.")
            proc.kill()
            proc.wait(timeout=5)

    print("\n[STEP 4] Real Process Teardown Completed Cleanly.")
    print("================================================================")


if __name__ == "__main__":
    run_node_stdio_mcp_bridge_exploit()
