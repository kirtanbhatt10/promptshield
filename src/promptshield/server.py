"""A zero-dependency HTTP sidecar so any language can use promptshield.

Run ``promptshield serve`` (or the Docker image) next to a Node, Go or Java
service and call it over localhost:

=========================  =================================================
``GET  /healthz``          liveness probe
``GET  /v1/detectors``     detector list
``POST /v1/scan``          ``{"text", "mode": "input"|"output", "canaries"}``
``POST /v1/scrub``         ``{"text", "canaries", "allowed_domains"}``
``POST /v1/spotlight``     ``{"text", "source", "mode"}``
=========================  =================================================

Set ``PROMPTSHIELD_TOKEN`` (or ``--token``) to require ``Authorization: Bearer``.
Request bodies are capped, scanned text is never logged, and every response is
JSON.
"""

from __future__ import annotations

import hmac
import json
import logging
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import __version__
from .detector import registry
from .policy import Policy
from .scanner import Scanner
from .scrub import scrub
from .spotlight import MODES, Spotlight

log = logging.getLogger("promptshield.server")
MAX_BODY = 1_000_000
MAX_CANARIES = 32


class _BadRequest(Exception):
    pass


def _text(body: dict[str, Any]) -> str:
    text = body.get("text")
    if not isinstance(text, str):
        raise _BadRequest("'text' must be a string")
    return text


def _str_list(body: dict[str, Any], key: str) -> list[str]:
    value = body.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value) or len(value) > MAX_CANARIES:
        raise _BadRequest(f"'{key}' must be a list of at most {MAX_CANARIES} strings")
    return value


def make_handler(policy: Policy, token: str | None = None) -> type[BaseHTTPRequestHandler]:
    default_scanner = Scanner(policy)
    detectors = [{"name": n, "kind": c.kind, "description": c.description} for n, c in registry().items()]

    def scan(body: dict[str, Any]) -> dict:
        mode = body.get("mode", "input")
        if mode not in ("input", "output"):
            raise _BadRequest("'mode' must be 'input' or 'output'")
        canaries = _str_list(body, "canaries")
        scanner = Scanner(policy, canaries=canaries) if canaries else default_scanner
        return scanner.scan(_text(body), mode).to_dict()

    def do_scrub(body: dict[str, Any]) -> dict:
        allowed = _str_list(body, "allowed_domains") or list(policy.allowed_domains)
        return scrub(_text(body), _str_list(body, "canaries"), allowed).to_dict()

    def spotlight(body: dict[str, Any]) -> dict:
        mode = body.get("mode", "delimit")
        if mode not in MODES:
            raise _BadRequest(f"'mode' must be one of {', '.join(MODES)}")
        spot = Spotlight(mode)
        return {"text": spot.wrap(_text(body), str(body.get("source", "external"))), "instructions": spot.instructions()}

    routes = {"/v1/scan": scan, "/v1/scrub": do_scrub, "/v1/spotlight": spotlight}

    class Handler(BaseHTTPRequestHandler):
        server_version = f"promptshield/{__version__}"
        sys_version = ""

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
            pass

        def _send(self, status: int, payload: dict) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)
            log.info(json.dumps({"method": self.command, "path": self.path, "status": status}))

        def _authorized(self) -> bool:
            if not token:
                return True
            header = self.headers.get("Authorization", "")
            return hmac.compare_digest(header.encode(), f"Bearer {token}".encode())

        def do_GET(self) -> None:  # noqa: N802 - stdlib naming
            if self.path == "/healthz":
                self._send(200, {"status": "ok", "version": __version__})
            elif not self._authorized():
                self._send(401, {"error": "unauthorized"})
            elif self.path == "/v1/detectors":
                self._send(200, {"detectors": detectors})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802 - stdlib naming
            route = routes.get(self.path)
            if route is None:
                self._send(404, {"error": "not found"})
                return
            if not self._authorized():
                self._send(401, {"error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send(411, {"error": "Content-Length required"})
                return
            if length < 0 or length > MAX_BODY:
                self._send(413, {"error": f"body must be at most {MAX_BODY} bytes"})
                return
            try:
                body = json.loads(self.rfile.read(length) or b"null")
                if not isinstance(body, dict):
                    raise _BadRequest("body must be a JSON object")
                started = time.perf_counter()
                result = route(body)
                result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send(400, {"error": "invalid JSON"})
            except _BadRequest as exc:
                self._send(400, {"error": str(exc)})
            except Exception:  # pragma: no cover - last-resort guard
                log.exception("unhandled error")
                self._send(500, {"error": "internal error"})
            else:
                self._send(200, result)

    return Handler


def make_server(host: str = "127.0.0.1", port: int = 8787, policy: Policy | None = None, token: str | None = None):
    """Build (but do not start) the HTTP server. ``port=0`` picks a free port."""
    server = ThreadingHTTPServer((host, port), make_handler(policy or Policy(), token))
    server.daemon_threads = True
    return server


def serve(host: str = "127.0.0.1", port: int = 8787, policy: Policy | None = None, token: str | None = None) -> None:
    server = make_server(host, port, policy, token)
    actual_host, actual_port = server.server_address[:2]
    print(f"promptshield {__version__} listening on http://{actual_host}:{actual_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
