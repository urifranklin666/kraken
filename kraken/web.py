"""Local dashboard and JSON API (stdlib only, HTTP + optional HTTPS/SSE)."""

from __future__ import annotations

import ipaddress
import json
import logging
import mimetypes
import os
import queue
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .config import Config

_log = logging.getLogger("kraken.web")

_STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".json": "application/json; charset=utf-8",
}


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], app: Any, cfg: Config):
        self.app = app
        self.cfg = cfg
        super().__init__(address, handler)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "KRAKEN"
    sys_version = ""

    @property
    def app(self) -> Any:
        return self.server.app  # type: ignore[attr-defined]

    @property
    def cfg(self) -> Config:
        return self.server.cfg  # type: ignore[attr-defined]

    # ------------------------------------------------------------------ helpers
    def log_message(self, fmt: str, *args: Any) -> None:
        _log.debug("%s - %s", self.client_address[0], fmt % args)

    def _is_local(self) -> bool:
        try:
            return ipaddress.ip_address(self.client_address[0]).is_loopback
        except ValueError:
            return False

    def _provided_token(self) -> str:
        token = self.headers.get("X-Kraken-Token", "").strip()
        if not token:
            auth = self.headers.get("Authorization", "")
            if auth.lower().startswith("bearer "):
                token = auth[7:].strip()
        if not token:
            token = parse_qs(urlparse(self.path).query).get("token", [""])[0]
        return token

    def _authorized(self, *, write: bool = False, sensitive: bool = False) -> bool:
        if self._is_local():
            return True
        if not write and not sensitive and self.cfg.general.open_read:
            return True
        return self.app.token_matches(self._provided_token())

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_error_json(self, status: int, message: str) -> None:
        self._send_json({"ok": False, "error": message}, status)

    def _assets_dir(self) -> Path:
        configured = Path(self.cfg.general.assets_dir)
        if configured.is_dir():
            return configured
        return Path(__file__).parent / "assets"

    def _serve_file(self, path: Path, *, download: str | None = None) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            self._send_error_json(404, "not found")
            return
        content_type = _STATIC_TYPES.get(path.suffix.lower())
        if content_type is None:
            content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        if download:
            safe = download.replace('"', "").replace("\r", "").replace("\n", "")
            self.send_header("Content-Disposition", f'attachment; filename="{safe}"')
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # ---------------------------------------------------------------------- GET
    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urlparse(self.path)
            path = unquote(parsed.path)
            query = parse_qs(parsed.query)
            if path == "/healthz":
                self._send_json({"ok": True, "app": "kraken"})
                return
            if path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
                return
            if path == "/api/events":
                if not self._authorized():
                    self._send_error_json(401, "token required")
                    return
                self._serve_events()
                return
            if path == "/api/portal":
                ap = self.cfg.ap
                self._send_json(
                    {
                        "ok": True,
                        "ssid": ap.ssid,
                        "portal_ip": self.cfg.portal_ip,
                        "subnet": ap.subnet,
                        "portal": ap.portal,
                        "client_isolation": ap.client_isolation,
                    }
                )
                return
            if path == "/api/status":
                if not self._authorized():
                    self._send_error_json(401, "token required")
                    return
                self._send_json(self.app.status())
                return
            if path == "/api/config":
                if not self._authorized():
                    self._send_error_json(401, "token required")
                    return
                self._send_json({"ok": True, "config": self.cfg.as_public_dict()})
                return
            if path == "/api/aps":
                if not self._authorized():
                    self._send_error_json(401, "token required")
                    return
                self._send_json(
                    {"ok": True, "aps": self.app.store.aps(int(query.get("limit", [300])[0]))}
                )
                return
            if path == "/api/clients":
                if not self._authorized():
                    self._send_error_json(401, "token required")
                    return
                self._send_json(
                    {
                        "ok": True,
                        "clients": self.app.store.clients(int(query.get("limit", [300])[0])),
                    }
                )
                return
            if path == "/api/handshakes":
                if not self._authorized():
                    self._send_error_json(401, "token required")
                    return
                self._send_json(
                    {
                        "ok": True,
                        "handshakes": self.app.store.handshakes(
                            int(query.get("limit", [100])[0])
                        ),
                    }
                )
                return
            if path == "/api/logs":
                if not self._authorized(sensitive=True):
                    self._send_error_json(401, "token required")
                    return
                lines = int(query.get("lines", [200])[0])
                from .util import tail_lines

                self._send_json(
                    {
                        "ok": True,
                        "logs": tail_lines(
                            Path(self.cfg.general.log_dir) / "kraken.log", lines
                        ),
                    }
                )
                return
            if path.startswith("/api/capture/"):
                if not self._authorized(sensitive=True):
                    self._send_error_json(401, "token required")
                    return
                try:
                    handshake_id = int(path.rsplit("/", 1)[1])
                except ValueError:
                    self._send_error_json(400, "invalid capture id")
                    return
                handshake = self.app.store.handshake(handshake_id)
                if not handshake:
                    self._send_error_json(404, "capture not found")
                    return
                capture = Path(handshake["path"]).resolve()
                captures_root = (Path(self.cfg.general.data_dir) / "captures").resolve()
                if not (capture.is_file() and capture.is_relative_to(captures_root)):
                    self._send_error_json(404, "capture file missing")
                    return
                self._serve_file(capture, download=capture.name)
                return

            if path in ("/", "/index.html", "/dashboard"):
                self._serve_file(self._assets_dir() / "dashboard.html")
                return
            if path in ("/portal", "/portal.html"):
                self._serve_file(self._assets_dir() / "portal.html")
                return
            if path.startswith("/assets/"):
                name = path[len("/assets/") :]
                if not name or "/" in name or "\\" in name or name.startswith("."):
                    self._send_error_json(404, "not found")
                    return
                assets = self._assets_dir().resolve()
                candidate = (assets / name).resolve()
                if not candidate.is_relative_to(assets) or not candidate.is_file():
                    self._send_error_json(404, "not found")
                    return
                self._serve_file(candidate)
                return
            self._send_error_json(404, "not found")
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:  # noqa: BLE001
            _log.exception("GET %s failed", self.path)
            try:
                self._send_error_json(500, f"{type(exc).__name__}: {exc}")
            except Exception:
                pass

    # --------------------------------------------------------------------- POST
    def do_POST(self) -> None:  # noqa: N802
        try:
            if not self._authorized(write=True):
                self._send_error_json(401, "token required for changes")
                return
            parsed = urlparse(self.path)
            path = parsed.path
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0 or length > 65536:
                self._send_error_json(411, "a JSON body is required (max 64 KiB)")
                return
            try:
                body = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._send_error_json(400, f"invalid JSON: {exc}")
                return
            if not isinstance(body, dict):
                self._send_error_json(400, "JSON body must be an object")
                return

            routes = {
                "/api/mode": ("mode", lambda data: {"cmd": "mode", "value": data.get("mode")}),
                "/api/ap": ("ap", lambda data: {"cmd": "ap", **data}),
                "/api/mitm": (
                    "mitm",
                    lambda data: {"cmd": "mitm", "enabled": bool(data.get("enabled"))},
                ),
                "/api/aggressive": (
                    "aggressive",
                    lambda data: {"cmd": "aggressive", "enabled": bool(data.get("enabled"))},
                ),
                "/api/panic": ("panic", lambda data: {"cmd": "panic"}),
                "/api/verify": (
                    "verify",
                    lambda data: {"cmd": "verify", "id": int(data.get("id", 0))},
                ),
            }
            if path not in routes:
                self._send_error_json(404, "not found")
                return
            _, builder = routes[path]
            result = self.app.handle_command(builder(body))
            if result.get("ok"):
                try:
                    self.app.write_status()
                except Exception:
                    pass
            status = 200 if result.get("ok") else 400
            if not result.get("ok") and "authorized" in str(result.get("error", "")).lower():
                status = 403
            self._send_json(result, status)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:  # noqa: BLE001
            _log.exception("POST %s failed", self.path)
            try:
                self._send_error_json(500, f"{type(exc).__name__}: {exc}")
            except Exception:
                pass

    # ---------------------------------------------------------------------- SSE
    def _serve_events(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        subscriber = self.app.subscribe()
        try:
            self.wfile.write(b": kraken connected\n\n")
            self.wfile.flush()
            try:
                initial = {"type": "status", "data": self.app.status()}
                self.wfile.write(
                    f"data: {json.dumps(initial, default=str)}\n\n".encode("utf-8")
                )
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return
            while not self.app.stopping:
                try:
                    message = subscriber.get(timeout=15)
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    continue
                payload = json.dumps(message, default=str, separators=(",", ":"))
                self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.app.unsubscribe(subscriber)
            self.close_connection = True


class WebServer:
    def __init__(self, app: Any, cfg: Config):
        self.app = app
        self.cfg = cfg
        self._servers: list[_Server] = []
        self._threads: list[threading.Thread] = []
        self._log = logging.getLogger("kraken.web")
        self.error = ""

    def start(self) -> None:
        if self._servers:
            return
        try:
            self._start_http()
        except OSError as exc:
            self.error = f"cannot bind HTTP {self.cfg.general.bind}:{self.cfg.general.http_port}: {exc}"
            self._log.error(self.error)
            raise
        cert = Path(self.cfg.general.cert_file)
        key = Path(self.cfg.general.key_file)
        if cert.is_file() and key.is_file():
            try:
                self._start_https(cert, key)
            except (OSError, ssl.SSLError) as exc:
                self.error = f"HTTPS disabled: {exc}"
                self._log.warning(self.error)
        else:
            self._log.warning("TLS certificate missing; dashboard is HTTP only")

    def _start_http(self) -> None:
        server = _Server(
            (self.cfg.general.bind, int(self.cfg.general.http_port)), _Handler, self.app, self.cfg
        )
        thread = threading.Thread(
            target=server.serve_forever, name="kraken-http", daemon=True
        )
        thread.start()
        self._servers.append(server)
        self._threads.append(thread)
        self._log.info(
            "dashboard on http://%s:%s", self.cfg.general.bind, self.cfg.general.http_port
        )

    def _start_https(self, cert: Path, key: Path) -> None:
        server = _Server(
            (self.cfg.general.bind, int(self.cfg.general.https_port)), _Handler, self.app, self.cfg
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(cert), str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(
            target=server.serve_forever, name="kraken-https", daemon=True
        )
        thread.start()
        self._servers.append(server)
        self._threads.append(thread)
        self._log.info(
            "secure dashboard on https://%s:%s", self.cfg.general.bind, self.cfg.general.https_port
        )

    def stop(self) -> None:
        for server in self._servers:
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass
        for thread in self._threads:
            thread.join(timeout=2)
        self._servers.clear()
        self._threads.clear()

    def status(self) -> dict[str, Any]:
        return {
            "http": int(self.cfg.general.http_port),
            "https": int(self.cfg.general.https_port) if len(self._servers) > 1 else None,
            "error": self.error,
        }
