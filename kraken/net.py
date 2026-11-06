"""Linux networking helpers: interfaces, NetworkManager, nftables, uplink."""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import time
from pathlib import Path
from typing import Any

from .util import CommandError, output_of, rfkill_unblock_wifi, run, run_ok, which, write_atomic

NFT_TABLE = "inet kraken"


def iface_exists(iface: str) -> bool:
    return Path(f"/sys/class/net/{iface}").exists()


def is_wireless(iface: str) -> bool:
    return Path(f"/sys/class/net/{iface}/wireless").exists()


def list_wireless() -> list[str]:
    root = Path("/sys/class/net")
    if not root.exists():
        return []
    return sorted(
        entry.name for entry in root.iterdir() if (entry / "wireless").exists()
    )


def supports_monitor(iface: str) -> bool:
    try:
        phy = Path(f"/sys/class/net/{iface}/phy80211/name").read_text(encoding="utf-8").strip()
    except OSError:
        return False
    if not phy:
        return False
    info = output_of(["iw", "phy", phy, "info"], timeout=6)
    in_modes = False
    for line in info.splitlines():
        stripped = line.strip()
        if stripped.startswith("Supported interface modes:"):
            in_modes = True
            continue
        if in_modes:
            if stripped.startswith("* "):
                if stripped[2:].strip() == "monitor":
                    return True
            else:
                break
    return False


def ensure_radio_roles(ap_iface: str, monitor_iface: str) -> tuple[str, str]:
    """Ensure ``ap_iface`` and ``monitor_iface`` match their hardware roles.

    On Raspberry Pi 4 booting with an external USB monitor adapter (e.g. RT5370),
    kernel probe timing can enumerate the USB adapter as ``wlan0`` and the
    onboard ``brcmfmac`` radio as ``wlan1``.  When ``monitor_iface`` lacks
    monitor-mode support and ``ap_iface`` has it, swap the kernel interface
    names (or fall back to swapping the role assignment).
    """
    if (
        not ap_iface
        or not monitor_iface
        or ap_iface == monitor_iface
        or not is_wireless(ap_iface)
        or not is_wireless(monitor_iface)
    ):
        return ap_iface, monitor_iface
    if supports_monitor(monitor_iface) or not supports_monitor(ap_iface):
        return ap_iface, monitor_iface

    tmp = "kraken_swap0"
    nm_set_managed(ap_iface, False)
    nm_set_managed(monitor_iface, False)
    link_down(ap_iface)
    link_down(monitor_iface)
    if iface_exists(tmp):
        link_down(tmp)
    if run_ok(["ip", "link", "set", "dev", ap_iface, "name", tmp], timeout=6):
        if run_ok(["ip", "link", "set", "dev", monitor_iface, "name", ap_iface], timeout=6):
            if run_ok(["ip", "link", "set", "dev", tmp, "name", monitor_iface], timeout=6):
                return ap_iface, monitor_iface
            run_ok(["ip", "link", "set", "dev", ap_iface, "name", monitor_iface], timeout=6)
        run_ok(["ip", "link", "set", "dev", tmp, "name", ap_iface], timeout=6)

    if supports_monitor(monitor_iface):
        return ap_iface, monitor_iface
    return monitor_iface, ap_iface


def nm_set_managed(iface: str, managed: bool) -> bool:
    if not run_ok(["nmcli", "--version"], timeout=5):
        return False
    return run_ok(
        ["nmcli", "device", "set", iface, "managed", "yes" if managed else "no"],
        timeout=8,
    )


def link_up(iface: str) -> bool:
    if run_ok(["ip", "link", "set", "dev", iface, "up"], timeout=6):
        return True
    rfkill_unblock_wifi()
    return run_ok(["ip", "link", "set", "dev", iface, "up"], timeout=6)


def link_down(iface: str) -> bool:
    return run_ok(["ip", "link", "set", "dev", iface, "down"], timeout=6)


def set_type(iface: str, iface_type: str) -> bool:
    return run_ok(["iw", "dev", iface, "set", "type", iface_type], timeout=8)


def get_type(iface: str) -> str:
    info = output_of(["iw", "dev", iface, "info"])
    for line in info.splitlines():
        line = line.strip()
        if line.startswith("type "):
            return line.split(None, 1)[1]
    return "unknown"


def get_channel(iface: str) -> int | None:
    info = output_of(["iw", "dev", iface, "info"])
    for line in info.splitlines():
        line = line.strip()
        if line.startswith("channel "):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def set_channel(iface: str, channel: int) -> bool:
    if run_ok(["iw", "dev", iface, "set", "channel", str(channel)], timeout=6):
        return True
    # Some drivers want an explicit width for 5 GHz channels.
    return run_ok(
        ["iw", "dev", iface, "set", "channel", str(channel), "HT20"], timeout=6
    )


def set_power_save(iface: str, enabled: bool) -> bool:
    return run_ok(
        ["iw", "dev", iface, "set", "power_save", "on" if enabled else "off"],
        timeout=6,
    )


def set_reg_domain(code: str) -> bool:
    return run_ok(["iw", "reg", "set", code], timeout=6)


def get_ip(iface: str) -> str | None:
    out = output_of(["ip", "-4", "-o", "addr", "show", "dev", iface])
    for line in out.splitlines():
        parts = line.split()
        if "inet" in parts:
            try:
                return parts[parts.index("inet") + 1].split("/")[0]
            except (IndexError, ValueError):
                continue
    return None


def get_mac(iface: str) -> str | None:
    try:
        return Path(f"/sys/class/net/{iface}/address").read_text().strip().lower()
    except OSError:
        return None


def _hex_ipv4(value: str) -> str:
    # /proc/net/route stores the address little-endian in hex.
    packed = struct.pack("<L", int(value, 16))
    return socket.inet_ntoa(packed)


def default_routes() -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    try:
        lines = Path("/proc/net/route").read_text().splitlines()[1:]
    except OSError:
        return routes
    for line in lines:
        parts = line.split()
        if len(parts) < 8:
            continue
        if parts[1] != "00000000" or parts[7] != "00000000":
            continue
        try:
            metric = int(parts[6])
        except ValueError:
            metric = 0
        routes.append(
            {
                "iface": parts[0],
                "gateway": _hex_ipv4(parts[2]),
                "metric": metric,
                "ip": get_ip(parts[0]),
            }
        )
    routes.sort(key=lambda route: route["metric"])
    return routes


def detect_uplink(preferred: str = "auto", exclude: tuple[str, ...] = ()) -> dict[str, Any]:
    routes = [route for route in default_routes() if route["iface"] not in exclude]
    chosen: dict[str, Any] | None = None
    if preferred and preferred != "auto":
        for route in routes:
            if route["iface"] == preferred:
                chosen = route
                break
        if chosen is None:
            chosen = {
                "iface": preferred,
                "gateway": None,
                "metric": None,
                "ip": get_ip(preferred),
                "up": False,
            }
    else:
        for route in routes:
            if route["iface"].startswith("eth"):
                chosen = route
                break
        if chosen is None and routes:
            chosen = routes[0]
    if chosen is None:
        return {"iface": None, "gateway": None, "ip": None, "metric": None, "up": False}
    chosen = dict(chosen)
    chosen["up"] = True
    return chosen


def set_ip_forward(enabled: bool) -> None:
    value = "1" if enabled else "0"
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text(value)
    except OSError:
        pass
    run_ok(["sysctl", "-q", "-w", f"net.ipv4.ip_forward={value}"], timeout=5)


def nft_available() -> bool:
    return run_ok(["nft", "--version"], timeout=5)


def nft_apply(rules: str) -> None:
    path = Path("/run/kraken/nftables.nft")
    write_atomic(path, rules, mode=0o600)
    check = run(["nft", "-c", "-f", str(path)], timeout=10)
    if check.returncode != 0:
        raise CommandError(f"nft syntax error: {check.stderr.strip()}")
    nft_clear()
    proc = run(["nft", "-f", str(path)], timeout=10)
    if proc.returncode != 0:
        raise CommandError(f"nft apply failed: {proc.stderr.strip()}")


def nft_clear() -> None:
    run_ok(["nft", "delete", "table"] + NFT_TABLE.split(), timeout=8)


def station_dump(iface: str) -> list[dict[str, Any]]:
    out = output_of(["iw", "dev", iface, "station", "dump"], timeout=8)
    stations: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("Station "):
            if current:
                stations.append(current)
            mac = stripped.split()[1].lower()
            current = {"mac": mac}
        elif current is not None and ":" in stripped:
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip()
            if key == "signal":
                try:
                    current["rssi"] = int(value.split()[0])
                except (ValueError, IndexError):
                    pass
            elif key in ("rx bytes", "tx bytes"):
                try:
                    current[key.replace(" ", "_")] = int(value)
                except ValueError:
                    pass
            elif key == "connected time":
                try:
                    current["connected_s"] = int(value.split()[0])
                except (ValueError, IndexError):
                    pass
            elif key == "inactive time":
                try:
                    current["inactive_ms"] = int(value.split()[0])
                except (ValueError, IndexError):
                    pass
    if current:
        stations.append(current)
    return stations


def read_dhcp_leases(path: str | Path) -> list[dict[str, Any]]:
    leases: list[dict[str, Any]] = []
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return leases
    now = time.time()
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            expires = float(parts[0])
        except ValueError:
            continue
        if expires != 0 and expires < now:
            continue
        leases.append(
            {
                "expires": expires,
                "mac": parts[1].lower(),
                "ip": parts[2],
                "hostname": parts[3] if len(parts) > 3 else "",
            }
        )
    return leases


def subnet_hosts(subnet: str) -> tuple[str, int]:
    interface = ipaddress.ip_interface(subnet)
    return str(interface.ip), interface.network.num_addresses
