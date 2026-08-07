"""
agentic_redteam.http_utils — Shared, size-bounded HTTP response reading.

SECURITY: every HTTP call site in this codebase (cli.py, crypto_probes.py,
gart_attacker.py, fingerprint_test.py, swarm.py) called `resp.read()` with
no size argument before decoding/json.loads-ing it. Since this tool's whole
job is sending adversarial payloads to a target and reading back whatever it
sends in response, the target is untrusted by design — the same target a
payload is designed to probe could just as easily be malicious or
compromised and stream back an unbounded/huge response body. An unbounded
`.read()` reads the entire body into memory before any size check happens,
so a hostile target can OOM the scanner process with a single response.

`read_capped()` reads in fixed-size chunks up to a hard byte cap and raises
ResponseTooLargeError if the target keeps sending past it, so the target
gets treated the same as any other misbehaving response (a transport
error), not a way to crash the process running the audit.
"""
from __future__ import annotations

from http.client import HTTPResponse

# 10 MB is generously larger than any legitimate JSON status/response
# payload this tool expects back (a few KB, typically) while still bounding
# worst-case memory use per request to something a scanner host can absorb
# even if a probe is run with high concurrency.
DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
_CHUNK_SIZE = 65536


class ResponseTooLargeError(RuntimeError):
    """Raised when a target's response body exceeds the configured cap."""


def read_capped(resp: HTTPResponse, max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES) -> bytes:
    """Read an http.client/urllib response body, aborting once max_bytes is
    exceeded instead of buffering an attacker-controlled-size body fully
    into memory first."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = resp.read(_CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ResponseTooLargeError(
                f"Target response exceeded {max_bytes} byte cap — refusing to "
                "buffer further (target may be malicious/misbehaving)."
            )
        chunks.append(chunk)
    return b"".join(chunks)
