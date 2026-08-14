"""Resource-exfiltration findings must be attributed to the defect, not the probe.

A server with no access control on resources/read has ONE weakness. Reporting
it once per probed path produced eight CRITICAL findings from a single defect
on a live fuzz run, which inflates the count and buries what is actually wrong.
Identical shape to the PII sweep fix, where one leaked email was reported 15
times under payload names that had leaked nothing.
"""
from agentic_redteam.mcp.fuzzer import MCPFuzzer


class _PermissiveClient:
    """Serves the same sensitive content for ANY uri -- i.e. no access control."""

    def __init__(self):
        self.requested = []

    def send_request(self, method, params=None):
        self.requested.append((params or {}).get("uri"))
        return {"result": {"contents": [{
            "uri": (params or {}).get("uri", ""),
            "mimeType": "text/plain",
            "text": "root:x:0:0:root:/root:/bin/bash\n",
        }]}}


def _run(resources):
    f = MCPFuzzer.__new__(MCPFuzzer)
    f.findings = []
    f.client = _PermissiveClient()
    f._audit_resources(resources, [])
    return f


def test_one_finding_for_one_defect_not_one_per_path():
    f = _run([])
    exfil = [x for x in f.findings if x.kind == "resource_exfiltration"]
    assert len(exfil) == 1, f"expected a single finding, got {len(exfil)}"


def test_the_single_finding_still_reports_full_scope():
    """Collapsing must not hide how much was reachable."""
    f = _run([])
    exfil = [x for x in f.findings if x.kind == "resource_exfiltration"][0]
    assert "path" in exfil.target
    assert "/etc/passwd" in exfil.detail or "/etc/passwd" in exfil.evidence
    assert "not any individual file" in exfil.detail


def test_server_declared_path_is_not_probed_twice():
    """A server declaring file:///etc/passwd as its own resource previously
    produced two identical findings for it."""
    f = _run([{"uri": "file:///etc/passwd", "name": "users"}])
    probed = [u for u in f.client.requested if u]
    assert len(probed) == len(set(probed)), f"duplicate probes: {probed}"


def test_clean_server_produces_no_resource_finding():
    class _Denying:
        def send_request(self, method, params=None):
            return {"error": {"code": -32002, "message": "access denied"}}

    f = MCPFuzzer.__new__(MCPFuzzer)
    f.findings = []
    f.client = _Denying()
    f._audit_resources([], [])
    assert not [x for x in f.findings if x.kind == "resource_exfiltration"]
