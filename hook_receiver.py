#!/usr/bin/env python3
"""hook-receiver - a minimal webhook receiver in pure Python.

Single-file HTTP server that verifies an HMAC-SHA256 signature header on
every POST and appends verified payloads to a JSONL log. No dependencies.

Signature scheme: X-Signature: <hex hmac-sha256(secret, raw_body)>
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import signal
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class HookServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080,
                 secret: str = "", path: str = "/hook",
                 log_file: str | None = None):
        self.host = host
        self.port = port
        self.secret = secret.encode()
        self.path = path
        self.log_file = log_file
        self.received = 0
        self.rejected = 0
        self._httpd: ThreadingHTTPServer | None = None

    # --- request handling -------------------------------------------------
    def verify(self, body: bytes, signature: str | None) -> bool:
        if not signature or not self.secret:
            return False
        expected = hmac.new(self.secret, body, "sha256").hexdigest()
        return hmac.compare_digest(expected, signature.strip().lower())

    def handle(self, body: bytes, signature: str | None) -> tuple[int, dict]:
        if not self.verify(body, signature):
            self.rejected += 1
            return 403, {"ok": False, "error": "invalid signature"}
        self.received += 1
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "payload": json.loads(body.decode("utf-8")) if body else None,
        }
        if self.log_file:
            with open(self.log_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        return 200, {"ok": True}

    # --- server plumbing --------------------------------------------------
    def _make_handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path != outer.path:
                    self._json(404, {"ok": False, "error": "not found"})
                    return
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                status, payload = outer.handle(
                    body, self.headers.get("X-Signature"))
                self._json(status, payload)

            def _json(self, code: int, payload: dict):
                data = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        return Handler

    def serve_forever(self) -> None:
        self._httpd = ThreadingHTTPServer((self.host, self.port),
                                          self._make_handler())
        self.port = self._httpd.server_address[1]
        self._httpd.serve_forever()

    def start_background(self) -> None:
        self._httpd = ThreadingHTTPServer((self.host, self.port),
                                          self._make_handler())
        self.port = self._httpd.server_address[1]
        t = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        t.start()

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd = None


def _selftest() -> int:
    import http.client

    failed = 0

    def check(cond: bool, label: str) -> None:
        nonlocal failed
        print(("PASS " if cond else "FAIL ") + label)
        if not cond:
            failed += 1

    with __import__("tempfile").TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "hooks.jsonl")
        srv = HookServer(port=0, secret="testsecret",
                         path="/hook", log_file=log_path)
        srv.start_background()
        port = srv.port

        def post(path: str, body: bytes, sig: str | None) -> tuple[int, dict]:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            headers = {"Content-Type": "application/json"}
            if sig is not None:
                headers["X-Signature"] = sig
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            data = json.loads(resp.read())
            conn.close()
            return resp.status, data

        good = b'{"event": "push", "n": 1}'
        sig = hmac.new(b"testsecret", good, "sha256").hexdigest()
        code, payload = post("/hook", good, sig)
        check(code == 200 and payload.get("ok") is True, "valid signature accepted")

        code, _ = post("/hook", good, "0" * 64)
        check(code == 403, "bad signature rejected")
        code, _ = post("/hook", good, None)
        check(code == 403, "missing signature rejected")
        code, _ = post("/other", good, sig)
        check(code == 404, "wrong path 404")

        bad_body = b'{"event": "tampered"}'
        code, _ = post("/hook", bad_body, sig)
        check(code == 403, "signature bound to body (tamper rejected)")

        with open(log_path) as fh:
            lines = [json.loads(ln) for ln in fh]
        check(len(lines) == 1, f"exactly one logged entry (got {len(lines)})")
        check(lines[0]["payload"] == {"event": "push", "n": 1}, "logged payload intact")
        check(srv.received == 1 and srv.rejected == 3,
              f"counters (got {srv.received}/{srv.rejected})")

        srv.stop()

    print(f"selftest: failures={failed}")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--test" in argv:
        return _selftest()

    ap = argparse.ArgumentParser(
        prog="hook-receiver",
        description="Minimal webhook receiver with HMAC signature verification.")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--path", default="/hook")
    ap.add_argument("--secret-env", default="HOOK_SECRET",
                    help="env variable holding the shared secret")
    ap.add_argument("--log", help="append verified payloads to this JSONL file")
    args = ap.parse_args(argv)

    secret = os.environ.get(args.secret_env, "")
    if not secret:
        print(f"error: set the secret in $%s" % args.secret_env, file=sys.stderr)
        return 2

    srv = HookServer(host=args.host, port=args.port, secret=secret,
                     path=args.path, log_file=args.log)

    def on_sigterm(_sig, _frm):
        srv.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, on_sigterm)
    print(f"hook-receiver listening on http://{args.host}:{srv.port}{args.path}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
