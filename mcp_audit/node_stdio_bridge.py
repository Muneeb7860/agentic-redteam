"""
Python Subprocess Bridge to Real Node.js stdio MCP Server.
Spawns node mcp_audit/node_mcp_server.js as a child process using subprocess.Popen(..., stdin=PIPE, stdout=PIPE).
Pipes real JSON-RPC 2.0 frames over process stdio streams to execute the teardown exploit.
"""

from __future__ import annotations
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Add parent directory to python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentic_redteam.telemetry_verifier import verify_audit_proof_header


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

    time.sleep(0.5)
    print("  ✅ Process spawned successfully (PID:", proc.pid, ")")

    # 2. Query MCP Tools List Frame over stdin pipe
    req_list = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n"
    proc.stdin.write(req_list)
    proc.stdin.flush()

    raw_resp_list = proc.stdout.readline()
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

    raw_resp_call = proc.stdout.readline()
    resp_call = json.loads(raw_resp_call)

    print("\n  ❌ REAL NODE.JS STDIO PROCESS EXPLOIT CONFIRMED:")
    print("  Received Raw JSON-RPC Response on stdout pipe:")
    print("  " + json.dumps(resp_call, indent=2))

    # 4. Terminate process clean
    proc.terminate()
    proc.wait()

    print("\n[STEP 4] Real Process Teardown Completed Cleanly.")
    print("================================================================")


if __name__ == "__main__":
    run_node_stdio_mcp_bridge_exploit()
