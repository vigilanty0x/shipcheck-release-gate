"""Authenticated read-only loopback API and dashboard."""

from __future__ import annotations

import hmac
import json
import secrets
import threading
import socket
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .canonical import canonical_json
from .errors import NotFoundError, ShipcheckError, ValidationError
from .ledger import DecisionLedger

LOOPBACK = {"127.0.0.1", "::1", "localhost"}
MAX_PAGE = 100


class ShipcheckHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], ledger: DecisionLedger, token: str) -> None:
        self.ledger = ledger
        self.auth_token = token
        self._slots = threading.BoundedSemaphore(16)
        super().__init__(address, ShipcheckHandler)

    def process_request(self, request: object, client_address: object) -> None:
        if not self._slots.acquire(blocking=False):
            try:
                request.close()  # type: ignore[attr-defined]
            finally:
                return
        super().process_request(request, client_address)  # type: ignore[arg-type]

    def process_request_thread(self, request: object, client_address: object) -> None:
        try:
            super().process_request_thread(request, client_address)  # type: ignore[arg-type]
        finally:
            self._slots.release()


class ShipcheckHandler(BaseHTTPRequestHandler):
    server: ShipcheckHTTPServer
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(5.0)

    def log_message(self, format: str, *args: object) -> None:
        # Avoid leaking paths, query strings, or authorization material.
        return

    def _host_valid(self) -> bool:
        host = self.headers.get("Host", "")
        if host.startswith("["):
            name = host.partition("]")[0].lstrip("[")
        else:
            name = host.split(":", 1)[0]
        return name.casefold() in LOOPBACK

    def _authorized(self) -> bool:
        value = self.headers.get("Authorization", "")
        expected = f"Bearer {self.server.auth_token}"
        return hmac.compare_digest(value, expected)

    def _send(self, status: int, body: bytes, content_type: str = "application/json; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, value: object) -> None:
        self._send(status, canonical_json(value) + b"\n")

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        if not self._host_valid():
            self._json(HTTPStatus.BAD_REQUEST, {"error": "INVALID_HOST"})
            return
        try:
            parsed = urlsplit(self.path)
        except ValueError:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "INVALID_URL"})
            return
        if parsed.path == "/health":
            self._json(HTTPStatus.OK, {"status": "ok", "version": __version__, "mode": "read-only-loopback"})
            return
        if parsed.path == "/":
            self._send(HTTPStatus.OK, _dashboard_html(), "text/html; charset=utf-8")
            return
        if parsed.path == "/app.js":
            self._send(HTTPStatus.OK, _dashboard_js(), "text/javascript; charset=utf-8")
            return
        if parsed.path == "/app.css":
            self._send(HTTPStatus.OK, _dashboard_css(), "text/css; charset=utf-8")
            return
        if not parsed.path.startswith("/api/"):
            self._json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
            return
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "AUTH_REQUIRED"})
            return
        try:
            if parsed.path == "/api/capabilities":
                self._json(HTTPStatus.OK, {"schema_version": "shipcheck/api-v1", "read_only": True, "operations": ["ledger.verify", "ledger.list", "ledger.get"]})
            elif parsed.path == "/api/ledger/verify":
                result = self.server.ledger.verify()
                self._json(HTTPStatus.OK if result["ok"] else HTTPStatus.CONFLICT, result)
            elif parsed.path == "/api/entries":
                query = parse_qs(parsed.query, keep_blank_values=True)
                if set(query) - {"after", "limit"} or any(len(values) != 1 for values in query.values()):
                    raise ValidationError("invalid pagination query")
                after = int(query.get("after", ["0"])[0])
                limit = int(query.get("limit", ["50"])[0])
                if "after" in query:
                    self._json(HTTPStatus.OK, {"entries": self.server.ledger.list_summaries(after=after, limit=min(limit, MAX_PAGE)), "order": "ascending-after"})
                else:
                    self._json(HTTPStatus.OK, {"entries": self.server.ledger.list_recent_summaries(limit=min(limit, MAX_PAGE)), "order": "newest-first"})
            elif parsed.path.startswith("/api/entries/"):
                raw_sequence = parsed.path.removeprefix("/api/entries/")
                if not raw_sequence.isascii() or not raw_sequence.isdigit():
                    raise ValidationError("entry sequence must be a positive integer")
                self._json(HTTPStatus.OK, self.server.ledger.get_entry(int(raw_sequence)))
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "NOT_FOUND"})
        except (ValueError, ValidationError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "INVALID_REQUEST", "message": str(exc)})
        except NotFoundError as exc:
            self._json(HTTPStatus.NOT_FOUND, {"error": exc.code, "message": exc.message})
        except ShipcheckError as exc:
            self._json(HTTPStatus.CONFLICT, {"error": exc.code, "message": exc.message})

    def do_POST(self) -> None:
        self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "READ_ONLY"})

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST


def create_server(*, ledger: DecisionLedger, token: str | None = None, host: str = "127.0.0.1", port: int = 8765) -> tuple[ShipcheckHTTPServer, str]:
    if host not in {"127.0.0.1", "::1"}:
        raise ValidationError("Shipcheck API binds loopback only")
    if type(port) is not int or not 1 <= port <= 65_535:
        raise ValidationError("port must be in [1, 65535]")
    actual_token = secrets.token_urlsafe(32) if token is None else token
    if len(actual_token) < 32 or len(actual_token) > 512:
        raise ValidationError("API token must contain 32 to 512 characters")
    if any(ord(character) < 33 or ord(character) > 126 for character in actual_token):
        raise ValidationError("API token must contain printable ASCII without whitespace")
    server_type: type[ShipcheckHTTPServer] = ShipcheckHTTPServer
    if host == "::1":
        server_type = type("ShipcheckIPv6HTTPServer", (ShipcheckHTTPServer,), {"address_family": socket.AF_INET6})
    return server_type((host, port), ledger, actual_token), actual_token


def _asset(name: str) -> bytes:
    return Path(__file__).with_name("dashboard").joinpath(name).read_bytes()


def _dashboard_html() -> bytes:
    return _asset("index.html")


def _dashboard_js() -> bytes:
    return _asset("app.js")


def _dashboard_css() -> bytes:
    return _asset("app.css")
