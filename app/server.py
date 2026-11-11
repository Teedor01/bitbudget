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
                if method == "GET" and path == "/api/mode":
                    return self._send(200, svc.mode_info())           
                if method == "GET" and path == "/api/chain":
                    return self._send(200, svc.chain_head())          
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


def build_service(args):
    """Default: local simulation. `--anchor near`: live NEAR testnet session (module imported lazily, loopback only)."""
    if args.anchor == "local":
        return Service()
    if args.host not in LOOPBACK:
        raise SystemExit("--anchor near refuses non-loopback hosts: this server signs writes with the operator's "
                         "account, so it must not be reachable from other machines")
    missing = [f for f in ("store", "contract", "writer") if not getattr(args, f)]
    if missing:
        raise SystemExit("--anchor near needs --" + ", --".join(missing))
    from app.near_mode import LiveConfig, NearModeError, build_live_session      
    cfg = LiveConfig(store=args.store, contract=args.contract, writer=args.writer, rpc_url=args.rpc,
                     network=args.network, sign_with=args.sign_with, near_cli=args.near_cli,
                     confirm_timeout=args.confirm_timeout, deploy_tx=args.deploy_tx)
    try:
        return Service(live=build_live_session(cfg))
    except NearModeError as e:
        raise SystemExit("cannot start live NEAR mode (nothing was served, nothing was written): " + str(e))


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="Bit Budget demo server. Default: LOCAL SIMULATION. "
                                             "--anchor near: live NEAR testnet anchor (operator-run).")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--anchor", choices=("local", "near"), default="local")
    ap.add_argument("--store", help="near mode: directory created by scripts/near_live_check.py init")
    ap.add_argument("--contract", help="near mode: deployed anchor contract account (testnet)")
    ap.add_argument("--writer", help="near mode: the signing account this server uses for writes")
    ap.add_argument("--rpc", default="https://test.rpc.fastnear.com")
    ap.add_argument("--network", default="testnet", choices=("testnet",))
    ap.add_argument("--sign-with", default="keychain", choices=("keychain", "legacy-keychain"))
    ap.add_argument("--near-cli", default="near", help="path to the near-cli-rs binary (v0.30.1 verified)")
    ap.add_argument("--confirm-timeout", type=float, default=45.0)
    ap.add_argument("--deploy-tx", help="near mode: deployment transaction id, shown as a read-only explorer link")
    return ap.parse_args(argv)


def main():
    a = parse_args()
    svc = build_service(a)
    srv = make_server(a.host, a.port, svc)
    url = f"http://{a.host}:{srv.server_address[1]}/"
    if svc.live is None:
        print(f"Bit Budget demo (LOCAL SIMULATION) on {url}  (Ctrl+C to stop)")
    else:
        print(f"Bit Budget demo (LIVE NEAR TESTNET) on {url}  (Ctrl+C to stop)")
        print(f"  contract: {svc.live.cfg.contract}   writes are signed by THIS server with account: {svc.live.cfg.writer}")
        print("  Visitors can read the chain head but cannot submit authorized writes.")
        print(f"  Operator token (owner view only; shown once, keep it private): {svc.live.owner_token}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
