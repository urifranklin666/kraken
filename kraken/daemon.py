"""KRAKEN daemon: mode state machine, IPC, status fan-out, watchdog."""

from __future__ import annotations

import grp
import hmac
import json
import logging
import os
import queue
import secrets
import shutil
import signal
import socket
import threading
import time
from pathlib import Path
from typing import Any

from . import APP_NAME, __version__, net
from .ap import APServe
from .capture import CaptureEngine, verify_capture
from .config import Config, ConfigError, VALID_MODES
from .face import compute_face
from .mitm import MitmController
from .state import Store
from .util import (
    CommandError,
    ensure_dir,
    rfkill_unblock_wifi,
    human_uptime,
    run,
    setup_logging,
    tail_lines,
    write_atomic,
)
from .web import WebServer


class KrakenDaemon:
    def __init__(self, cfg: Config, *, authorized: bool = False):
        self.cfg = cfg
        self.authorized = authorized
        if not authorized:
            self.cfg.recon.aggressive = False
        self._log = logging.getLogger("kraken")
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._started_at = time.time()
        self._mode = "idle"
        self._subscribers: set[queue.Queue[dict[str, Any]]] = set()
        self._sub_lock = threading.Lock()
        self._last_status: dict[str, Any] = {}
        self._status_thread: threading.Thread | None = None
        self._ipc_thread: threading.Thread | None = None
        self._ipc_socket: socket.socket | None = None
        self._watchdog_last: dict[str, float] = {}
        self._uplink_cache: dict[str, Any] = {}
        self._uplink_ts = 0.0

        self.data_dir = ensure_dir(cfg.general.data_dir, 0o750)
        self.run_dir = ensure_dir(cfg.general.run_dir, 0o770)
        self.log_dir = ensure_dir(cfg.general.log_dir, 0o750)
        (self.data_dir / "captures").mkdir(parents=True, exist_ok=True)

        self.store = Store(self.data_dir / "kraken.db")
        self._load_persisted()
        self.capture = CaptureEngine(cfg, self.store)
        self.ap = APServe(cfg.ap, cfg.general, cfg.radio)
        self.mitm = MitmController(
            cfg.mitm,
            cfg.ap,
            cfg.general,
            ap_iface=cfg.radio.ap_iface,
            authorized=authorized,
        )
        self.web = WebServer(self, cfg)

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> dict[str, Any]:
        self._ensure_runtime()
        self.web.start()
        self._start_ipc()
        self._status_thread = threading.Thread(
            target=self._status_loop, name="kraken-status", daemon=True
        )
        self._status_thread.start()
        self.store.add_event("info", "system", f"{APP_NAME} {__version__} starting")
        result = self.set_mode(self.cfg.general.default_mode)
        self.store.add_event(
            "info",
            "system",
            f"{APP_NAME} ready in {self._mode} mode (authorized={self.authorized})",
        )
        return result

    def run_forever(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: self._stop.set())
        try:
            self.start()
            while not self._stop.wait(0.5):
                self._watchdog()
        finally:
            self.stop()

    def stop(self) -> None:
        if self._stop.is_set() and self._ipc_socket is None:
            return
        self._stop.set()
        self._log.info("shutting down")
        try:
            self.mitm.stop()
        except Exception:
            pass
        with self._lock:
            try:
                self.ap.stop()
            except Exception as exc:  # noqa: BLE001
                self._log.warning("AP stop: %s", exc)
            try:
                self.capture.stop()
            except Exception as exc:  # noqa: BLE001
                self._log.warning("capture stop: %s", exc)
        self._mode = "idle"
        try:
            self.web.stop()
        except Exception:
            pass
        self._stop_ipc()
        if self._status_thread and self._status_thread.is_alive():
            self._status_thread.join(timeout=3)
        try:
            self.store.add_event("info", "system", f"{APP_NAME} stopped")
        except Exception:
            pass
        self.store.close()
        self._log.info("stopped")

    # -------------------------------------------------------------------- modes
    def set_mode(self, mode: str) -> dict[str, Any]:
        if mode not in VALID_MODES:
            raise ValueError(f"unknown mode: {mode}")
        with self._lock:
            if mode == self._mode and self._components_ok(mode):
                return {"ok": True, "mode": mode, "errors": []}
            errors: list[str] = []
            try:
                self.mitm.stop()
            except Exception:
                pass
            try:
                self.ap.stop()
            except Exception as exc:  # noqa: BLE001
                errors.append(f"AP stop: {exc}")
            try:
                self.capture.stop()
            except Exception as exc:  # noqa: BLE001
                errors.append(f"capture stop: {exc}")

            if mode != "idle":
                ap_iface, mon_iface = net.ensure_radio_roles(
                    self.cfg.radio.ap_iface, self.cfg.radio.monitor_iface
                )
                self.cfg.radio.ap_iface = ap_iface
                self.cfg.radio.monitor_iface = mon_iface
                self.ap.iface = ap_iface
                self.capture.radio.iface = mon_iface
                self.mitm.ap_iface = ap_iface

            if mode in ("ap", "hybrid"):
                try:
                    self.ap.start()
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"AP: {exc}")
            if mode in ("recon", "hybrid"):
                try:
                    self.capture.start()
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"capture: {exc}")

            if mode in ("ap", "hybrid") and not self.ap.running:
                try:
                    self.ap.stop()
                except Exception:
                    pass
                if not any(err.startswith("AP:") for err in errors):
                    errors.append("AP: failed to stay running")
            if mode in ("recon", "hybrid") and not self.capture.running:
                try:
                    self.capture.stop()
                except Exception:
                    pass
                if not any(err.startswith("capture:") for err in errors):
                    errors.append("capture: failed to stay running")

            if mode == "hybrid" and not self.ap.running and not self.capture.running:
                mode = "idle"
            elif mode == "ap" and not self.ap.running:
                mode = "idle"
            elif mode == "recon" and not self.capture.running:
                mode = "idle"

            self._mode = mode
            self._started_at = time.time()
            if errors:
                for message in errors:
                    self.store.add_event("error", "mode", message)
            self.store.add_event("info", "mode", f"Mode set to {mode}")
            self._log.info("mode=%s errors=%s", mode, errors)
            try:
                self.write_status()
            except Exception:
                pass
            result: dict[str, Any] = {"ok": not errors, "mode": mode, "errors": errors}
            if errors:
                result["error"] = "; ".join(errors)
            return result

    def set_ap_config(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            old = (
                self.cfg.ap.ssid,
                self.cfg.ap.passphrase,
                self.cfg.ap.channel,
                self.cfg.ap.band,
                self.cfg.ap.portal,
                self.cfg.ap.dns_hijack,
            )
            try:
                if "ssid" in payload:
                    self.cfg.ap.ssid = str(payload["ssid"]).strip()
                if "passphrase" in payload:
                    self.cfg.ap.passphrase = str(payload["passphrase"])
                band = str(payload.get("band", self.cfg.ap.band))
                if band not in ("5", "2.4"):
                    raise ConfigError("band must be '5' or '2.4'")
                self.cfg.ap.band = band
                if "channel" in payload:
                    self.cfg.ap.channel = int(payload["channel"])
                if band == "5" and not 36 <= int(self.cfg.ap.channel) <= 165:
                    self.cfg.ap.channel = 36
                if band == "2.4" and not 1 <= int(self.cfg.ap.channel) <= 13:
                    self.cfg.ap.channel = 6
                if "portal" in payload:
                    self.cfg.ap.portal = bool(payload["portal"])
                if "dns_hijack" in payload:
                    self.cfg.ap.dns_hijack = bool(payload["dns_hijack"])
                self.cfg.validate()
            except (ConfigError, ValueError) as exc:
                (
                    self.cfg.ap.ssid,
                    self.cfg.ap.passphrase,
                    self.cfg.ap.channel,
                    self.cfg.ap.band,
                    self.cfg.ap.portal,
                    self.cfg.ap.dns_hijack,
                ) = old
                raise CommandError(str(exc)) from exc

            self._persist_ap()
            self.ap.cfg = self.cfg.ap
            self.mitm.ap_cfg = self.cfg.ap
            if self._mode in ("ap", "hybrid"):
                try:
                    self.ap.reload()
                except Exception as exc:  # noqa: BLE001
                    self.store.add_event("error", "ap", f"AP reload failed: {exc}")
                    raise CommandError(f"AP restart failed: {exc}") from exc
            self.store.add_event(
                "info",
                "ap",
                f"AP config: ssid={self.cfg.ap.ssid!r} band={self.cfg.ap.band} "
                f"channel={self.cfg.ap.channel} portal={self.cfg.ap.portal}",
            )
            return {"ok": True, "ap": self.ap.status()}

    def set_mitm(self, enabled: bool) -> dict[str, Any]:
        if enabled:
            self.mitm.start()
            self.store.add_event("warning", "mitm", "MITM enabled (authorized mode)")
        else:
            self.mitm.stop()
            self.store.add_event("info", "mitm", "MITM disabled")
        return {"ok": True, "mitm": self.mitm.status()}

    def set_aggressive(self, enabled: bool) -> dict[str, Any]:
        if enabled and not self.authorized:
            raise PermissionError(
                "aggressive deauthentication requires the daemon to be started with "
                "--authorized on networks you own or have written permission to test"
            )
        with self._lock:
            self.cfg.recon.aggressive = bool(enabled)
            self.capture.set_aggressive(bool(enabled))
            self.store.set_setting("recon.aggressive", "1" if enabled else "0")
            if enabled:
                self.store.add_event(
                    "warning",
                    "recon",
                    "Aggressive deauthentication ENABLED — authorized networks only",
                )
            else:
                self.store.add_event("info", "recon", "Aggressive deauthentication disabled")
            return {"ok": True, "aggressive": bool(enabled)}

    def panic(self) -> dict[str, Any]:
        self.mitm.stop()
        return self.set_mode("idle")

    # ------------------------------------------------------------------- status
    def status(self) -> dict[str, Any]:
        capture = self.capture.status()
        try:
            ap = self.ap.status()
        except Exception as exc:  # noqa: BLE001
            ap = {"enabled": False, "error": str(exc), "clients": []}
        try:
            mitm = self.mitm.status()
        except Exception as exc:  # noqa: BLE001
            mitm = {"available": False, "enabled": False, "error": str(exc)}
        counts = self.store.counts()
        recent = self.store.recent_counts(120)
        activity_age = capture.get("last_frame_age")
        if activity_age is None:
            activity_age = 9999.0
        face = compute_face(
            mode=self._mode,
            uptime=time.time() - self._started_at,
            handshakes_recent=recent["handshakes"],
            new_aps_recent=recent["new_aps"],
            seconds_since_activity=float(activity_age),
            hops=capture.get("hops", 0),
        )
        uplink = self._uplink()
        warnings = [
            item
            for item in (capture.get("error"), ap.get("error"), mitm.get("error"))
            if item
        ]
        try:
            free = shutil.disk_usage(self.data_dir).free
        except OSError:
            free = 0
        return {
            "ok": True,
            "app": APP_NAME,
            "version": __version__,
            "hostname": socket.gethostname(),
            "time": time.time(),
            "mode": self._mode,
            "authorized": self.authorized,
            "uptime": time.time() - self._started_at,
            "uptime_human": human_uptime(time.time() - self._started_at),
            "face": face.as_dict(),
            "counts": {
                **counts,
                "aps": max(counts["aps"], capture.get("aps", 0)),
                "clients": max(counts["clients"], capture.get("clients", 0)),
            },
            "channel": capture.get("channel") or ap.get("channel"),
            "capture": capture,
            "ap": ap,
            "mitm": mitm,
            "uplink": uplink,
            "aggressive": bool(self.capture.status().get("aggressive")),
            "config": self.cfg.as_public_dict(),
            "disk_free": free,
            "warnings": warnings,
            "events": self.store.events(60),
        }

    def _uplink(self) -> dict[str, Any]:
        now = time.monotonic()
        if self._uplink_cache and now - self._uplink_ts < 5:
            return self._uplink_cache
        cache = net.detect_uplink(
            self.cfg.radio.uplink_iface,
            exclude=(self.cfg.radio.ap_iface, self.cfg.radio.monitor_iface),
        )
        self._uplink_cache = cache
        self._uplink_ts = now
        return cache

    def write_status(self) -> dict[str, Any]:
        status = self.status()
        self._last_status = status
        path = Path(self.cfg.general.run_dir) / "status.json"
        write_atomic(path, json.dumps(status, separators=(",", ":"), default=str) + "\n")
        flat = {
            "mode": self._mode.upper(),
            "face": status["face"]["face"],
            "mood": status["face"]["mood"],
            "epoch": str(status["face"]["epoch"]),
            "aps": str(status["counts"]["aps"]),
            "clients": str(status["counts"]["clients"]),
            "handshakes": str(status["counts"]["handshakes"]),
            "verified": str(status["counts"]["verified"]),
            "channel": str(status["channel"] or "-"),
            "monitor": str(status["capture"].get("iface") or "-"),
            "hops": str(status["capture"].get("hops", 0)),
            "uplink": str(status["uplink"].get("iface") or "none"),
            "ap_ssid": str(status["ap"].get("ssid") or "-"),
            "ap_clients": str(len(status["ap"].get("clients", []))),
            "mitm": "on" if status["mitm"].get("enabled") else "off",
            "aggressive": "on" if status["aggressive"] else "off",
        }
        for name, value in flat.items():
            write_atomic(Path(self.cfg.general.run_dir) / name, value + "\n", mode=0o644)
        self._publish({"type": "status", "data": status})
        return status

    def _status_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.write_status()
            except Exception as exc:  # noqa: BLE001
                self._log.warning("status update failed: %s", exc)
            self._stop.wait(2.0)

    def _components_ok(self, mode: str) -> bool:
        if mode == "hybrid":
            return self.ap.running and self.capture.running
        if mode == "ap":
            return self.ap.running
        if mode == "recon":
            return self.capture.running
        return True

    def _watchdog(self) -> None:
        if self._mode == "idle" or self._stop.is_set():
            return
        now = time.monotonic()
        if self._mode in ("ap", "hybrid") and not self.ap.running:
            if now - self._watchdog_last.get("ap", 0) > 45:
                self._watchdog_last["ap"] = now
                self.store.add_event("warning", "watchdog", "AP died; restarting")
                try:
                    self.ap.start()
                except Exception as exc:  # noqa: BLE001
                    self.store.add_event("error", "watchdog", f"AP restart failed: {exc}")
        if self._mode in ("recon", "hybrid") and not self.capture.running:
            if now - self._watchdog_last.get("capture", 0) > 45:
                self._watchdog_last["capture"] = now
                self.store.add_event("warning", "watchdog", "Capture died; restarting")
                try:
                    self.capture.start()
                except Exception as exc:  # noqa: BLE001
                    self.store.add_event("error", "watchdog", f"Capture restart failed: {exc}")

    # ---------------------------------------------------------------- commands
    def handle_command(self, command: dict[str, Any]) -> dict[str, Any]:
        action = str(command.get("cmd") or command.get("action") or "").lower()
        try:
            if action in ("ping", "hello"):
                return {"ok": True, "app": APP_NAME, "version": __version__}
            if action == "status":
                return {"ok": True, "status": self.status()}
            if action == "mode":
                mode = str(command.get("value") or command.get("mode") or "")
                return self.set_mode(mode)
            if action == "ap":
                return self.set_ap_config(command)
            if action == "mitm":
                return self.set_mitm(bool(command.get("enabled")))
            if action == "aggressive":
                return self.set_aggressive(bool(command.get("enabled")))
            if action == "panic":
                return self.panic()
            if action == "aps":
                return {"ok": True, "aps": self.store.aps(int(command.get("limit", 300)))}
            if action == "clients":
                return {
                    "ok": True,
                    "clients": self.store.clients(int(command.get("limit", 300))),
                }
            if action == "handshakes":
                return {
                    "ok": True,
                    "handshakes": self.store.handshakes(int(command.get("limit", 100))),
                }
            if action == "events":
                return {
                    "ok": True,
                    "events": self.store.events(int(command.get("limit", 100))),
                }
            if action == "verify":
                handshake_id = int(command.get("id", 0))
                handshake = self.store.handshake(handshake_id)
                if not handshake:
                    return {"ok": False, "error": f"no handshake #{handshake_id}"}
                verified, note = verify_capture(handshake["path"])
                self.store.mark_verified(handshake_id, verified, note)
                return {
                    "ok": True,
                    "verified": verified,
                    "note": note,
                    "handshakes": self.store.handshakes(100),
                }
            if action == "logs":
                return {
                    "ok": True,
                    "logs": tail_lines(self.log_dir / "kraken.log", int(command.get("lines", 200))),
                }
            return {"ok": False, "error": f"unknown command: {action}"}
        except (CommandError, ConfigError, ValueError, PermissionError) as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            self._log.exception("command failed: %s", action)
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    # --------------------------------------------------------------------- IPC
    def _start_ipc(self) -> None:
        path = Path(self.cfg.general.run_dir) / "control.sock"
        if path.exists():
            try:
                path.unlink()
            except OSError:
                pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(path))
        sock.listen(16)
        sock.settimeout(1.0)
        try:
            gid = grp.getgrnam("kraken").gr_gid
            os.chown(path, 0, gid)
            os.chmod(path, 0o660)
        except (KeyError, OSError):
            os.chmod(path, 0o660)
        self._ipc_socket = sock
        self._ipc_thread = threading.Thread(
            target=self._ipc_loop, name="kraken-ipc", daemon=True
        )
        self._ipc_thread.start()

    def _ipc_loop(self) -> None:
        assert self._ipc_socket is not None
        sock = self._ipc_socket
        while not self._stop.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._ipc_connection, args=(conn,), daemon=True
            ).start()

    def _ipc_connection(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(15)
            chunks = b""
            while b"\n" not in chunks and len(chunks) < 65536:
                block = conn.recv(4096)
                if not block:
                    break
                chunks += block
            line = chunks.split(b"\n", 1)[0]
            command = json.loads(line.decode("utf-8")) if line else {}
            response = self.handle_command(command)
            conn.sendall((json.dumps(response, default=str) + "\n").encode("utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            try:
                conn.sendall(
                    (json.dumps({"ok": False, "error": str(exc)}) + "\n").encode("utf-8")
                )
            except OSError:
                pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _stop_ipc(self) -> None:
        if self._ipc_socket is not None:
            try:
                self._ipc_socket.close()
            except OSError:
                pass
            self._ipc_socket = None
        path = Path(self.cfg.general.run_dir) / "control.sock"
        try:
            path.unlink()
        except OSError:
            pass
        if self._ipc_thread and self._ipc_thread.is_alive():
            self._ipc_thread.join(timeout=2)

    # ------------------------------------------------------------------- events
    def subscribe(self) -> queue.Queue[dict[str, Any]]:
        subscriber: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=8)
        with self._sub_lock:
            self._subscribers.add(subscriber)
        return subscriber

    def unsubscribe(self, subscriber: queue.Queue[dict[str, Any]]) -> None:
        with self._sub_lock:
            self._subscribers.discard(subscriber)

    def _publish(self, message: dict[str, Any]) -> None:
        with self._sub_lock:
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber.put_nowait(message)
            except queue.Full:
                pass

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    # ------------------------------------------------------------------ runtime
    def _ensure_runtime(self) -> None:
        token_path = Path(self.cfg.general.token_file)
        if not token_path.exists():
            token = secrets.token_hex(24)
            write_atomic(token_path, token + "\n", mode=0o640)
            self._chown_kraken(token_path)
            self._log.info("generated API token at %s", token_path)
        else:
            try:
                os.chmod(token_path, 0o640)
            except OSError:
                pass
        cert = Path(self.cfg.general.cert_file)
        key = Path(self.cfg.general.key_file)
        if not cert.exists() or not key.exists():
            self._generate_certificate(cert, key)
        rfkill_unblock_wifi()
        try:
            os.chmod(self.run_dir, 0o770)
            os.chmod(self.data_dir, 0o750)
            os.chmod(self.log_dir, 0o750)
            os.chmod(token_path.parent, 0o750)
        except OSError:
            pass
        for d in (self.run_dir, self.data_dir, self.log_dir, token_path.parent):
            self._chown_kraken(d)

    def _chown_kraken(self, path: Path) -> None:
        try:
            gid = grp.getgrnam("kraken").gr_gid
            os.chown(path, 0, gid)
        except (KeyError, OSError):
            pass

    def _generate_certificate(self, cert: Path, key: Path) -> None:
        try:
            cert.parent.mkdir(parents=True, exist_ok=True)
            run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "825",
                    "-subj",
                    "/CN=kraken.local",
                    "-addext",
                    "subjectAltName=DNS:kraken.local,IP:10.13.37.1,IP:127.0.0.1",
                ],
                timeout=30,
            )
            os.chmod(key, 0o640)
            os.chmod(cert, 0o644)
            self._chown_kraken(key)
            self._log.info("generated self-signed TLS certificate")
        except Exception as exc:  # noqa: BLE001
            self._log.warning("cannot generate TLS certificate: %s", exc)

    def read_token(self) -> str:
        try:
            return Path(self.cfg.general.token_file).read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def token_matches(self, candidate: str) -> bool:
        expected = self.read_token()
        return bool(expected and candidate and hmac.compare_digest(expected, candidate))

    def _load_persisted(self) -> None:
        settings = {
            "ap.ssid": "ssid",
            "ap.passphrase": "passphrase",
            "ap.channel": "channel",
            "ap.band": "band",
            "ap.portal": "portal",
        }
        changed = False
        for key, attribute in settings.items():
            value = self.store.get_setting(key)
            if value is None:
                continue
            if attribute in ("channel",):
                try:
                    setattr(self.cfg.ap, attribute, int(value))
                except ValueError:
                    continue
            elif attribute == "portal":
                setattr(self.cfg.ap, attribute, value == "1")
            else:
                setattr(self.cfg.ap, attribute, value)
            changed = True
        aggressive = self.store.get_setting("recon.aggressive")
        if aggressive is not None:
            self.cfg.recon.aggressive = aggressive == "1"
            changed = True
        if changed:
            try:
                self.cfg.validate()
            except ConfigError as exc:
                self._log.warning("ignoring persisted settings: %s", exc)

    def _persist_ap(self) -> None:
        self.store.set_setting("ap.ssid", self.cfg.ap.ssid)
        self.store.set_setting("ap.passphrase", self.cfg.ap.passphrase)
        self.store.set_setting("ap.channel", str(self.cfg.ap.channel))
        self.store.set_setting("ap.band", self.cfg.ap.band)
        self.store.set_setting("ap.portal", "1" if self.cfg.ap.portal else "0")


def run_daemon(cfg: Config, *, authorized: bool = False) -> int:
    setup_logging(Path(cfg.general.log_dir) / "kraken.log")
    daemon = KrakenDaemon(cfg, authorized=authorized)
    daemon.run_forever()
    return 0
