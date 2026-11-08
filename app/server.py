"""HTTP backend (standard library only). Binds to 127.0.0.1 by default. Run:  python3 -m app.server --port 8000"""
import argparse
import json
import pathlib
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.service import ApiError, Service

WEB = pathlib.Path(__file__).resolve().parent.parent / "web"
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/index.html": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "application/javascript; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8")}
SESSION_RE = re.compile(r"^/api/sessions/([A-Za-z0-9_-]{1,64})(/query|/attack)?$")
MAX_BODY = 4096
CSP = "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
LOOPBACK = ("127.0.0.1", "localhost", "::1", "")


def make_server(host="127.0.0.1", port=8000, service=None):
    svc = service or Service()
    allowed_hosts = set()         

    class Handler(BaseHTTPRequestHandler):
        server_version = "BitBudgetDemo/0.1"

        def log_message(self, *a):        
            pass

        def _send(self, status, payload, ctype="application/json; charset=utf-8", raw=None):
            body = raw if raw is not None else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", CSP)
            self.end_headers()
            self.wfile.write(body)

        def _json_body(self):
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise ApiError(400, "bad Content-Length")
            if n < 0:
                raise ApiError(400, "bad Content-Length")
            if n > MAX_BODY:
                self.rfile.read(min(n, 65536))       
                self.close_connection = True
                raise ApiError(413, "request body too large")
            raw = self.rfile.read(n) if n else b"{}"
            try:
                obj = json.loads(raw.decode() or "{}")
            except (ValueError, UnicodeDecodeError):
                raise ApiError(400, "body must be valid JSON")
            if not isinstance(obj, dict):
                raise ApiError(400, "body must be a JSON object")
            return obj

        def _dispatch(self, method):
            try:
                if allowed_hosts and (self.headers.get("Host") or "").lower() not in allowed_hosts:
                    raise ApiError(403, "bad Host header")
                if method == "POST":
                    ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                    if ctype != "application/json":         
                        raise ApiError(415, "Content-Type must be application/json")
                path = self.path.split("?", 1)[0]
                if method == "GET" and path in STATIC:
                    name, ctype = STATIC[path]
                    return self._send(200, None, ctype, raw=(WEB / name).read_bytes())
                if method == "GET" and path == "/api/demo-story":
                    return self._send(200, svc.demo_story())
                if method == "POST" and path == "/api/sessions":
                    return self._send(201, svc.create_session(self._json_body()))
                m = SESSION_RE.match(path)
                if m:
                    sid, action = m.groups()
                    token = self.headers.get("X-Owner-Token") or ""
                    if method == "GET" and action is None:
                        return self._send(200, svc.owner_view(sid, token))
                    if method == "POST" and action == "/query":
                        return self._send(200, svc.query(sid, self._json_body()))
                    if method == "POST" and action == "/attack":
                        return self._send(200, svc.attack(sid, token, self._json_body()))
                raise ApiError(404, "not found")
            except ApiError as e:
                self._send(e.status, {"error": e.message})
            except Exception:             # never leak internals
                self._send(500, {"error": "internal error"})

        def do_GET(self): self._dispatch("GET")
        def do_POST(self): self._dispatch("POST")

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.service = svc
    if host in LOOPBACK:
        p = srv.server_address[1]
        allowed_hosts.update({f"127.0.0.1:{p}", f"localhost:{p}", f"[::1]:{p}"})
    return srv


def main():
    ap = argparse.ArgumentParser(description="Bit Budget local demo server (simulation only)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    srv = make_server(a.host, a.port)
    print(f"Bit Budget demo (LOCAL SIMULATION) on http://{a.host}:{srv.server_address[1]}/  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
