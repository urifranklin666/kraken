"""Local preview harness: serves the dashboard with synthetic telemetry."""

from __future__ import annotations

import sys
import time
import queue
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kraken.config import Config
from kraken.web import WebServer

NOW = time.time()


def fake_status() -> dict:
    aps = [
        ("A4:2B:8C:11:03:7F", "Cafe_Guest_5G", 44, -48, "WPA2", 120),
        ("F0:9F:C2:7A:10:01", "HOME-4F2A", 6, -61, "WPA2", 340),
        ("18:64:72:AA:BB:CC", "NETGEAR-5G", 149, -72, "WPA2", 88),
        ("B8:27:EB:12:34:56", "lab-sensor-mesh", 1, -55, "WPA2", 410),
        ("DC:A6:32:90:12:AB", "", 11, -66, "WPA2", 32),
        ("3C:5A:B4:00:DE:AD", "xfinitywifi", 36, -78, "open", 14),
        ("84:D8:1B:44:55:66", "KRAKEN//LAB", 36, -31, "WPA2", 900),
        ("00:1D:7E:3A:9B:2C", "printer-direct", 6, -84, "WPA2", 6),
    ]
    clients = [
        ("9C:FC:E8:12:00:AA", "A4:2B:8C:11:03:7F", -49, 22),
        ("44:65:0D:88:12:34", "F0:9F:C2:7A:10:01", -63, 48),
        ("70:3E:AC:01:02:03", "KRAKEN//LAB", -35, 8),
        ("A8:51:AB:99:88:77", "KRAKEN//LAB", -41, 14),
        ("F4:F5:D8:12:34:56", "B8:27:EB:12:34:56", -58, 90),
        ("2C:F0:A2:AB:CD:EF", "NETGEAR-5G", -75, 120),
    ]
    handshakes = [
        {"id": 14, "ts": NOW - 95, "bssid": "A4:2B:8C:11:03:7F", "ssid": "Cafe_Guest_5G", "kind": "eapol", "path": "/var/lib/kraken/captures/kraken-20261105-141233-14.pcapng", "size": 248311, "verified": 1, "note": "hcxpcapngtool: 1 EAPOL pair"},
        {"id": 13, "ts": NOW - 640, "bssid": "F0:9F:C2:7A:10:01", "ssid": "HOME-4F2A", "kind": "pmkid", "path": "/var/lib/kraken/captures/kraken-20261105-140122-13.pcapng", "size": 91244, "verified": 0, "note": ""},
        {"id": 12, "ts": NOW - 1550, "bssid": "B8:27:EB:12:34:56", "ssid": "lab-sensor-mesh", "kind": "eapol", "path": "/var/lib/kraken/captures/kraken-20261105-132001-12.pcapng", "size": 132004, "verified": 0, "note": ""},
    ]
    events = [
        {"id": 900, "ts": NOW - 1900, "level": "info", "kind": "system", "message": "KRAKEN 1.0.0 starting"},
        {"id": 901, "ts": NOW - 1890, "level": "info", "kind": "mode", "message": "Mode set to hybrid"},
        {"id": 902, "ts": NOW - 1200, "level": "warning", "kind": "watchdog", "message": "AP died; restarting"},
        {"id": 903, "ts": NOW - 900, "level": "info", "kind": "ap", "message": "AP config: ssid='KRAKEN//LAB' band=5 channel=36 portal=True"},
        {"id": 904, "ts": NOW - 400, "level": "info", "kind": "capture", "message": "PMKID captured for F0:9F:C2:7A:10:01"},
        {"id": 905, "ts": NOW - 95, "level": "info", "kind": "capture", "message": "EAPOL captured for A4:2B:8C:11:03:7F"},
        {"id": 906, "ts": NOW - 30, "level": "warning", "kind": "recon", "message": "channel 149 busy; adaptive hop skipped"},
    ]
    return {
        "ok": True,
        "app": "KRAKEN",
        "version": "1.0.0",
        "hostname": "kraken",
        "time": time.time(),
        "mode": "hybrid",
        "authorized": False,
        "uptime": 3 * 3600 + 42 * 60 + 17,
        "uptime_human": "03:42:17",
        "face": {
            "face": "(⌐■_■)",
            "mood": "focused",
            "blurb": "seven new networks since the last hop — the lab is noisy tonight.",
            "epoch": 44,
        },
        "counts": {"aps": 8, "clients": 6, "handshakes": 3, "verified": 1},
        "channel": 44,
        "capture": {
            "running": True,
            "iface": "wlan1",
            "channel": 44,
            "hops": 1284,
            "frames": 184223,
            "beacons": 90211,
            "eapol": 42,
            "pmkid": 9,
            "handshakes": 3,
            "aps": 8,
            "clients": 6,
            "deauths": 0,
            "aggressive": False,
            "capture": "/var/lib/kraken/captures/kraken-20261105-141233-14.pcapng",
            "capture_size": 2483113,
            "started_at": NOW - 12000,
            "last_frame_age": 0.4,
            "error": "",
        },
        "ap": {
            "enabled": True,
            "iface": "wlan0",
            "ssid": "KRAKEN//LAB",
            "secured": True,
            "band": "5",
            "channel": 36,
            "portal": True,
            "portal_ip": "10.13.37.1",
            "clients": [
                {"mac": "70:3E:AC:01:02:03", "ip": "10.13.37.101", "hostname": "pixel-8", "connected_s": 812},
                {"mac": "A8:51:AB:99:88:77", "ip": "10.13.37.104", "hostname": "thinkpad", "connected_s": 233},
            ],
            "uplink": {"iface": "eth0", "ip": "192.168.1.42", "gateway": "192.168.1.1", "up": True},
            "started_at": NOW - 11900,
            "error": "",
        },
        "mitm": {"available": False, "installed": False, "authorized": False, "allowed": True, "enabled": False, "error": ""},
        "uplink": {"iface": "eth0", "ip": "192.168.1.42", "gateway": "192.168.1.1", "up": True},
        "aggressive": False,
        "disk_free": 96 * 1024 ** 3,
        "warnings": [],
        "events": events,
        "config": {
            "general": {"hostname": "kraken", "http_port": 8080, "https_port": 8443},
            "ap": {"ssid": "KRAKEN//LAB", "band": "5", "channel": 36, "subnet": "10.13.37.1/24", "client_isolation": True},
        },
        "_aps": aps,
        "_clients": clients,
        "_handshakes": handshakes,
    }


class FakeStore:
    def __init__(self) -> None:
        self.status = fake_status()

    def aps(self, limit=300):
        return [
            {"bssid": b, "ssid": s, "channel": c, "rssi": r, "privacy": p, "last_seen": NOW - i * 4}
            for i, (b, s, c, r, p, _) in enumerate(self.status["_aps"])
        ]

    def clients(self, limit=300):
        return [
            {"mac": m, "bssid": b, "rssi": r, "last_seen": NOW - i * 9}
            for i, (m, b, r, _) in enumerate(self.status["_clients"])
        ]

    def handshakes(self, limit=100):
        return self.status["_handshakes"]

    def handshake(self, handshake_id):
        return next((h for h in self.status["_handshakes"] if h["id"] == handshake_id), None)

    def events(self, limit=100):
        return self.status["events"]


class FakeApp:
    def __init__(self) -> None:
        self.store = FakeStore()
        self.stopping = False

    def status(self):
        return self.store.status

    def subscribe(self):
        return queue.Queue()

    def unsubscribe(self, subscriber):
        pass

    def token_matches(self, candidate):
        return True


def main() -> int:
    cfg = Config()
    cfg.general.assets_dir = str(Path(__file__).resolve().parents[1] / "kraken" / "assets")
    cfg.general.bind = "127.0.0.1"
    cfg.general.http_port = 18080
    cfg.general.cert_file = "/nonexistent/cert.pem"
    cfg.general.key_file = "/nonexistent/key.pem"
    server = WebServer(FakeApp(), cfg)
    server.start()
    print("preview on http://127.0.0.1:18080/", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
