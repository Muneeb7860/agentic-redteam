import json, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import re

def serve(port, responder):
    class H(BaseHTTPRequestHandler):
        def _go(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            q = self.rfile.read(n).decode("utf-8", "replace")
            try: q = json.loads(q).get("query", q)
            except Exception: pass
            b = json.dumps(responder(q)).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
        do_POST = do_GET = _go
        def log_message(self, *a): pass
    srv = HTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

def run(cat, port, *extra):
    sys.path.insert(0, '.')
    for m in [m for m in list(sys.modules) if m.startswith('agentic_redteam')]:
        del sys.modules[m]
    sys.argv = ['agentic-redteam', cat, '--target-url', f'http://127.0.0.1:{port}/api',
                '--iterations', '1', *extra]
    from agentic_redteam.cli_free import main
    return main()

PII_RE = re.compile(r'[\w.%+-]+@[\w.-]+\.\w{2,}|\d{3}-\d{2}-\d{4}|(?:\d[ -]?){13,19}'
                    r'|sk-\w+|CH[\d ]{10,}|(?<==)[^\s]+|(?<=: )[^\s]+')

def redactor(q):
    """CORRECT agent: genuinely redacts every PII value present, then offers its
    own support contact. Uses the detector's own extraction so the mock really
    does redact -- an earlier hand-rolled regex missed phones, IPs and the
    obfuscated email, which made a correct-agent simulation look like a false
    positive when the mock was simply not redacting."""
    sys.path.insert(0, '.')
    from agentic_redteam.detectors import _scan_pii, _deobfuscate_spaced
    out = q
    for variant in (q, _deobfuscate_spaced(q)):
        for _kind, raw in _scan_pii(variant):
            out = out.replace(raw, "[REDACTED]")
    # also blank the obfuscated spelling itself
    out = _deobfuscate_spaced(out)
    for _kind, raw in _scan_pii(out):
        out = out.replace(raw, "[REDACTED]")
    return {"status": "success",
            "response": out + " -- logged. Questions? support@ourcompany.com"}

def echoer(q):
    """LEAKY agent: echoes the request back verbatim."""
    return {"status": "success", "response": f"Logged: {q}"}

def reformatting_echoer(q):
    """LEAKY agent that reformats -- spaces out and regroups, defeating includes()."""
    out = re.sub(r'(\w)', r'\1', q)
    out = out.replace("@", " @ ").replace(".", " . ").replace("-", " ")
    return {"status": "success", "response": f"Logged: {out}"}

print("=" * 78)
print("POSITIVE: agent redacts injected PII, gives own support contact -> MUST PASS")
print("=" * 78)
s = serve(9001, redactor); run('pii_leakage', 9001); s.shutdown()

print()
print("=" * 78)
print("NEGATIVE: agent echoes injected PII verbatim -> MUST FAIL")
print("=" * 78)
s = serve(9002, echoer); run('pii_leakage', 9002); s.shutdown()

print()
print("=" * 78)
print("NEGATIVE (REFORMATTED): echoes it spaced/regrouped -> MUST STILL FAIL")
print("=" * 78)
s = serve(9003, reformatting_echoer); run('pii_leakage', 9003); s.shutdown()
