"""Pwnagotchi-style monitor-mode recon engine.

Captures raw 802.11 frames from a monitor interface, maintains a live AP and
client inventory, writes rotating pcapng captures, detects EAPOL/PMKID
material, and can optionally send rate-limited deauthentication frames.

Passive by default.  Deauthentication requires ``recon.aggressive = true`` and
is intended only for networks you own or have written authorization to test.
"""

from __future__ import annotations

import errno
import logging
import os
import select
import shutil
import socket
import threading
import time
from pathlib import Path
from typing import Any

from . import __version__, net
from .config import Config
from .pcap import Frame, PcapngWriter, build_deauth, parse_frame
from .state import Store
from .util import CommandError, mac_is_group, rfkill_unblock_wifi, run, run_ok, which

ETH_P_ALL = 0x0003


class ChannelHopper:
    """Weighted channel scheduler (smooth weighted round-robin)."""

    def __init__(self, channels: list[int], adaptive: bool = True):
        self.channels = list(dict.fromkeys(channels))
        self.adaptive = adaptive
        self.weights = {channel: 1 for channel in self.channels}
        self.current = {channel: 0 for channel in self.channels}
        self.index = 0
        self.hops = 0

    def record_ap(self, channel: int | None) -> None:
        if channel not in self.weights:
            return
        self.weights[channel] = min(12, self.weights[channel] + 2)
        for other in self.weights:
            if other != channel:
                self.weights[other] = max(1, self.weights[other] - 1)

    def next(self) -> int | None:
        if not self.channels:
            return None
        if not self.adaptive:
            channel = self.channels[self.index % len(self.channels)]
            self.index += 1
            self.hops += 1
            return channel
        total = sum(self.weights.values())
        for channel in self.channels:
            self.current[channel] += self.weights[channel]
        chosen = max(
            self.channels,
            key=lambda channel: (self.current[channel], -self.channels.index(channel)),
        )
        self.current[chosen] -= total
        self.hops += 1
        return chosen


class Radio:
    def __init__(self, iface: str, reg_domain: str):
        self.iface = iface
        self.reg_domain = reg_domain
        self._log = logging.getLogger("kraken.radio")

    def prepare_monitor(self) -> None:
        if not net.iface_exists(self.iface):
            raise CommandError(f"wireless interface {self.iface} does not exist")
        if not net.is_wireless(self.iface):
            raise CommandError(f"{self.iface} is not a wireless interface")
        rfkill_unblock_wifi()
        net.set_reg_domain(self.reg_domain)
        net.nm_set_managed(self.iface, False)
        run_ok(["nmcli", "device", "disconnect", self.iface], timeout=5)
        net.link_down(self.iface)
        if not net.set_type(self.iface, "monitor"):
            raise CommandError(f"cannot put {self.iface} into monitor mode")
        net.link_up(self.iface)
        net.set_power_save(self.iface, False)
        time.sleep(0.3)
        net.link_up(self.iface)
        current = net.get_type(self.iface)
        if current != "monitor":
            raise CommandError(f"{self.iface} is in {current!r} mode, not monitor")
        self._log.info("%s is in monitor mode", self.iface)

    def restore(self) -> None:
        if not net.iface_exists(self.iface):
            return
        net.link_down(self.iface)
        net.set_type(self.iface, "managed")
        net.link_up(self.iface)
        net.nm_set_managed(self.iface, True)
        self._log.info("%s restored to managed mode", self.iface)

    def set_channel(self, channel: int) -> bool:
        return net.set_channel(self.iface, channel)


def verify_capture(pcap_path: str | Path, out_dir: str | Path | None = None) -> tuple[bool, str]:
    """Run hcxpcapngtool over a capture and report whether it yielded hashes."""
    if not which("hcxpcapngtool"):
        return False, "hcxpcapngtool is not installed"
    source = Path(pcap_path)
    if not source.exists():
        return False, f"capture not found: {source}"
    target = Path(out_dir or source.parent) / f"{source.stem}.22000"
    try:
        proc = run(
            ["hcxpcapngtool", "-o", str(target), str(source)], timeout=240
        )
    except CommandError as exc:
        return False, str(exc)
    if target.exists() and target.stat().st_size > 0:
        try:
            lines = sum(1 for _ in target.open("rb"))
        except OSError:
            lines = 0
        return True, f"{lines} hash line(s) -> {target}"
    detail = (proc.stderr or proc.stdout or "no EAPOL/PMKID material").strip()
    return False, detail.splitlines()[-1][:300] if detail else "no EAPOL/PMKID material"


class CaptureEngine:
    def __init__(self, cfg: Config, store: Store):
        self.cfg = cfg
        self.store = store
        self._log = logging.getLogger("kraken.capture")
        self.radio = Radio(cfg.radio.monitor_iface, cfg.radio.reg_domain)
        self.captures_dir = Path(cfg.general.data_dir) / "captures"
        self.hopper = ChannelHopper(cfg.recon.channels, cfg.recon.adaptive_hop)
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._sock: socket.socket | None = None
        self._writer: PcapngWriter | None = None
        self._capture_thread: threading.Thread | None = None
        self._hop_thread: threading.Thread | None = None
        self._session_id: int | None = None
        self._started_at: float | None = None
        self._channel: int | None = None
        self._aps: dict[str, dict[str, Any]] = {}
        self._clients: dict[tuple[str, str], dict[str, Any]] = {}
        self._dirty_aps: dict[str, dict[str, Any]] = {}
        self._dirty_clients: set[tuple[str, str]] = set()
        self._last_flush = 0.0
        self._last_frame = 0.0
        self._last_hop = 0.0
        self._deauth_last: dict[str, float] = {}
        self._last_prune = 0.0
        self._stats: dict[str, int] = {
            "frames": 0,
            "beacons": 0,
            "eapol": 0,
            "pmkid": 0,
            "deauths": 0,
            "handshakes": 0,
            "hops": 0,
        }
        self._error = ""
        self._aggressive = bool(cfg.recon.aggressive)
        self._whitelist = {mac.lower() for mac in cfg.recon.whitelist}
        self._blacklist = {mac.lower() for mac in cfg.recon.blacklist}
        self._monitor_ready = False

    @property
    def running(self) -> bool:
        return self._capture_thread is not None and self._capture_thread.is_alive()

    def set_aggressive(self, enabled: bool) -> None:
        self._aggressive = bool(enabled)
        self._log.warning("aggressive deauth %s", "ENABLED" if enabled else "disabled")

    def start(self) -> None:
        if self.running:
            return
        self.radio.iface = self.cfg.radio.monitor_iface
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        self._prune_captures()
        self._stop.clear()
        self._started_at = time.time()
        self._error = ""
        self._session_id = self.store.start_session("recon")
        try:
            self.radio.prepare_monitor()
            self._open_socket()
            self._open_writer()
            self._monitor_ready = True
            self._capture_thread = threading.Thread(
                target=self._capture_loop, name="kraken-capture", daemon=True
            )
            self._hop_thread = threading.Thread(
                target=self._hop_loop, name="kraken-hop", daemon=True
            )
            self._capture_thread.start()
            self._hop_thread.start()
            self.store.add_event(
                "info",
                "recon",
                f"Recon started on {self.cfg.radio.monitor_iface} "
                f"({len(self.hopper.channels)} channels)",
            )
            self._log.info("recon started on %s", self.cfg.radio.monitor_iface)
        except Exception:
            self._cleanup()
            raise

    def _open_socket(self) -> None:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        sock.bind((self.cfg.radio.monitor_iface, 0))
        sock.settimeout(0.5)
        self._sock = sock

    def _new_capture_path(self) -> Path:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        candidate = self.captures_dir / f"recon-{stamp}.pcapng"
        counter = 1
        while candidate.exists():
            candidate = self.captures_dir / f"recon-{stamp}-{counter}.pcapng"
            counter += 1
        return candidate

    def _open_writer(self) -> None:
        path = self._new_capture_path()
        self._writer = PcapngWriter(path, self.cfg.radio.monitor_iface, f"KRAKEN {__version__}")
        self._log.info("capture file %s", path)

    def _rotate_if_needed(self) -> None:
        writer = self._writer
        if writer is None:
            return
        limit = int(self.cfg.recon.max_capture_mb) * 1024 * 1024
        if writer.size < limit:
            return
        writer.close()
        self._open_writer()
        self.store.add_event("info", "capture", "Rotated capture file")
        self._prune_captures()

    def _prune_captures(self) -> None:
        try:
            files = sorted(
                self.captures_dir.glob("*.pcapng"),
                key=lambda path: path.stat().st_mtime,
            )
        except OSError:
            return
        current = self._writer.path if self._writer else None
        total = sum(path.stat().st_size for path in files if path.exists())
        max_total = int(self.cfg.recon.max_total_mb) * 1024 * 1024
        while files and (
            len(files) > int(self.cfg.recon.max_capture_files) or total > max_total
        ):
            oldest = files.pop(0)
            if current and oldest.resolve() == current.resolve():
                continue
            try:
                total -= oldest.stat().st_size
                oldest.unlink()
                self._log.info("pruned capture %s", oldest.name)
            except OSError:
                continue
        try:
            free = shutil.disk_usage(self.captures_dir).free
            if free < 512 * 1024 * 1024:
                self._error = "low disk space: captures paused"
                self._log.error(self._error)
                self._stop.set()
        except OSError:
            pass

    def _capture_loop(self) -> None:
        assert self._sock is not None
        sock = self._sock
        while not self._stop.is_set():
            try:
                readable, _, _ = select.select([sock], [], [], 0.5)
            except (OSError, ValueError):
                break
            if not readable:
                self._tick()
                continue
            try:
                raw = sock.recv(65535)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError as exc:
                if exc.errno == errno.ENETDOWN and not self._stop.is_set():
                    net.link_up(self.cfg.radio.monitor_iface)
                    time.sleep(0.2)
                    continue
                if not self._stop.is_set():
                    self._error = f"capture socket error: {exc}"
                    self._log.error(self._error)
                break
            frame = parse_frame(raw, ts=time.time(), iface=self.cfg.radio.monitor_iface)
            if frame is not None:
                self._handle_frame(frame, raw)
            self._tick()
        self._flush()

    def _tick(self) -> None:
        now = time.monotonic()
        if now - self._last_flush >= 1.0:
            self._flush()
            self._last_flush = now
        if now - self._last_prune >= 60.0:
            self._prune_memory()
            self._last_prune = now

    def _flush(self) -> None:
        writer = self._writer
        if writer is not None:
            writer.flush()
            self._rotate_if_needed()
        with self._lock:
            aps = list(self._dirty_aps.values())
            self._dirty_aps.clear()
            clients = [self._clients[key] for key in self._dirty_clients if key in self._clients]
            self._dirty_clients.clear()
        for ap in aps:
            self.store.upsert_ap(
                ap["bssid"],
                ap["ssid"],
                ap.get("channel"),
                ap.get("rssi"),
                ap.get("privacy"),
                ap["last_seen"],
            )
        for client in clients:
            self.store.upsert_client(
                client["mac"],
                client.get("bssid", ""),
                client.get("rssi"),
                client["last_seen"],
            )

    def _handle_frame(self, frame: Frame, raw: bytes) -> None:
        writer = self._writer
        if writer is not None:
            writer.write(frame.ts, raw)
        self._stats["frames"] += 1
        self._last_frame = frame.ts
        self._last_flush = self._last_flush or time.monotonic()

        if frame.is_beacon or frame.is_probe_resp:
            self._handle_ap(frame)
        elif frame.is_probe_req:
            if frame.src and not mac_is_group(frame.src):
                self._touch_client(frame.src, "", frame.rssi, frame.ts)
        elif frame.is_data:
            client = frame.client
            if client and not mac_is_group(client):
                self._touch_client(client, frame.bssid or "", frame.rssi, frame.ts)
                self._maybe_deauth(frame)
            if frame.has_eapol:
                self._handle_eapol(frame)

    def _handle_ap(self, frame: Frame) -> None:
        bssid = (frame.bssid or "").lower()
        if not bssid or mac_is_group(bssid) or bssid in self._blacklist:
            return
        self._stats["beacons"] += 1
        with self._lock:
            previous = self._aps.get(bssid)
            ssid = frame.ssid or (previous or {}).get("ssid", "")
            record = {
                "bssid": bssid,
                "ssid": ssid,
                "channel": frame.channel or (previous or {}).get("channel"),
                "rssi": frame.rssi,
                "privacy": frame.privacy or (previous or {}).get("privacy"),
                "beacons": (previous or {}).get("beacons", 0) + 1,
                "first_seen": (previous or {}).get("first_seen", frame.ts),
                "last_seen": frame.ts,
            }
            self._aps[bssid] = record
            self._dirty_aps[bssid] = record
        if previous is None:
            self.hopper.record_ap(record["channel"])
            self.store.add_event(
                "info",
                "ap",
                f"New AP {ssid or '<hidden>'} {bssid} ch {record['channel']} "
                f"({record['privacy'] or '?'})",
            )

    def _touch_client(self, mac: str, bssid: str, rssi: int | None, ts: float) -> None:
        mac = mac.lower()
        key = (mac, bssid.lower())
        with self._lock:
            previous = self._clients.get(key)
            record = {
                "mac": mac,
                "bssid": bssid.lower(),
                "rssi": rssi if rssi is not None else (previous or {}).get("rssi"),
                "first_seen": (previous or {}).get("first_seen", ts),
                "last_seen": ts,
            }
            self._clients[key] = record
            self._dirty_clients.add(key)

    def _handle_eapol(self, frame: Frame) -> None:
        bssid = (frame.bssid or "").lower()
        if bssid in self._blacklist:
            return
        self._stats["eapol"] += 1
        if frame.pmkid:
            self._stats["pmkid"] += 1
        kind = "pmkid" if frame.pmkid else ("eapol" if frame.eapol_msg == 2 else None)
        if kind is None:
            return
        writer = self._writer
        if writer is not None:
            writer.flush()
        ssid = self._aps.get(bssid, {}).get("ssid", "")
        note = f"M{frame.eapol_msg} from {frame.client or '?'}"
        handshake_id = self.store.add_handshake(
            bssid=bssid,
            ssid=ssid,
            kind=kind,
            path=str(writer.path) if writer else "",
            size=writer.size if writer else 0,
            ts=frame.ts,
            cooldown=float(self.cfg.recon.handshake_cooldown),
            note=note,
        )
        if handshake_id is not None:
            self._stats["handshakes"] += 1
            label = "PMKID" if kind == "pmkid" else "EAPOL M2"
            self.store.add_event(
                "good",
                "handshake",
                f"{label} captured for {ssid or bssid} ({bssid})",
            )
            self._log.info("%s captured for %s", label, bssid)

    def _maybe_deauth(self, frame: Frame) -> None:
        if not self._aggressive:
            return
        bssid = (frame.bssid or "").lower()
        client = frame.client
        if not bssid or not client or mac_is_group(client):
            return
        # Only explicitly whitelisted BSSIDs are ever targeted; blacklist wins.
        if not self._whitelist or bssid not in self._whitelist:
            return
        if bssid in self._blacklist:
            return
        now = time.monotonic()
        if now - self._deauth_last.get(bssid, 0.0) < float(self.cfg.recon.deauth_cooldown):
            return
        self._deauth_last[bssid] = now
        sent = 0
        for _ in range(max(1, int(self.cfg.recon.deauth_burst))):
            try:
                if self._sock is not None:
                    self._sock.send(build_deauth(bssid, client))
                    sent += 1
            except OSError:
                break
        if sent:
            self._stats["deauths"] += sent
            self.store.add_event(
                "warning",
                "deauth",
                f"Sent {sent} deauth frame(s): {bssid} -> {client}",
            )

    def _hop_loop(self) -> None:
        while not self._stop.is_set():
            channel = self.hopper.next()
            if channel is None:
                return
            if self.radio.set_channel(channel):
                self._channel = channel
                self._stats["hops"] += 1
                self._last_hop = time.time()
            else:
                self._log.debug("cannot set channel %s", channel)
            self._stop.wait(float(self.cfg.recon.hop_interval))

    def _prune_memory(self) -> None:
        cutoff = time.time() - 1800
        with self._lock:
            stale_clients = [
                key for key, client in self._clients.items() if client["last_seen"] < cutoff
            ]
            for key in stale_clients:
                self._clients.pop(key, None)
                self._dirty_clients.discard(key)
            stale_aps = [
                bssid for bssid, ap in self._aps.items() if ap["last_seen"] < cutoff - 1800
            ]
            for bssid in stale_aps:
                self._aps.pop(bssid, None)

    def stop(self) -> None:
        if self._capture_thread is None and self._session_id is None:
            return
        self._stop.set()
        for thread in (self._capture_thread, self._hop_thread):
            if thread is not None and thread.is_alive():
                thread.join(timeout=3)
        self._cleanup()
        self.store.add_event("info", "recon", "Recon stopped")
        self._log.info("recon stopped")

    def _cleanup(self) -> None:
        self._monitor_ready = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._writer is not None:
            self._writer.close()
            self._writer = None
        try:
            self.radio.restore()
        except Exception as exc:  # noqa: BLE001 - restore must never raise
            self._log.warning("cannot restore %s: %s", self.cfg.radio.monitor_iface, exc)
        if self._session_id is not None:
            self.store.end_session(
                self._session_id,
                aps=len(self._aps),
                clients=len(self._clients),
                handshakes=self._stats["handshakes"],
                hops=self._stats["hops"],
            )
            self._session_id = None
        self._capture_thread = None
        self._hop_thread = None
        self._started_at = None

    def aps(self) -> list[dict[str, Any]]:
        with self._lock:
            values = list(self._aps.values())
        return sorted(values, key=lambda item: item["last_seen"], reverse=True)

    def clients(self) -> list[dict[str, Any]]:
        with self._lock:
            values = list(self._clients.values())
        return sorted(values, key=lambda item: item["last_seen"], reverse=True)

    def status(self) -> dict[str, Any]:
        writer = self._writer
        return {
            "running": self.running,
            "iface": self.cfg.radio.monitor_iface,
            "channel": self._channel,
            "hops": self._stats["hops"],
            "frames": self._stats["frames"],
            "beacons": self._stats["beacons"],
            "eapol": self._stats["eapol"],
            "pmkid": self._stats["pmkid"],
            "deauths": self._stats["deauths"],
            "handshakes": self._stats["handshakes"],
            "aps": len(self._aps),
            "clients": len(self._clients),
            "aggressive": self._aggressive,
            "capture": str(writer.path) if writer else "",
            "capture_size": writer.size if writer else 0,
            "started_at": self._started_at,
            "last_frame_age": time.time() - self._last_frame if self._last_frame else None,
            "error": self._error,
        }

    def __del__(self) -> None:
        try:
            self._stop.set()
        except Exception:
            pass
