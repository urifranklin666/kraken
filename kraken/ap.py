"""Captive-portal access point: hostapd + dnsmasq + nftables."""

from __future__ import annotations

import ipaddress
import logging
import time
from pathlib import Path
from typing import Any

from . import net
from .config import APConfig, GeneralConfig, RadioConfig
from .util import (
    CommandError,
    ManagedProcess,
    kill_stale,
    output_of,
    read_text,
    rfkill_unblock_wifi,
    run_ok,
    tail_lines,
)

_log = logging.getLogger("kraken.ap")


def render_hostapd(
    cfg: APConfig,
    iface: str,
    *,
    hw_mode: str | None = None,
    channel: int | None = None,
) -> str:
    mode = hw_mode or ("a" if cfg.band == "5" else "g")
    chan = channel or cfg.channel
    lines = [
        f"interface={iface}",
        "driver=nl80211",
        "ctrl_interface=/run/kraken/hostapd",
        "ctrl_interface_group=0",
        f"ssid={cfg.ssid}",
        f"country_code={cfg.country}",
        f"hw_mode={mode}",
        f"channel={chan}",
        "ieee80211d=1",
        "ieee80211n=1",
        "wmm_enabled=1",
        "beacon_int=100",
        "dtim_period=2",
        f"max_num_sta={cfg.max_clients}",
        "auth_algs=1",
        "macaddr_acl=0",
        "ignore_broadcast_ssid=0",
        "utf8_ssid=1",
    ]
    if cfg.client_isolation:
        lines.append("ap_isolate=1")
    if cfg.passphrase:
        lines += [
            "wpa=2",
            f"wpa_passphrase={cfg.passphrase}",
            "wpa_key_mgmt=WPA-PSK",
            "rsn_pairwise=CCMP",
        ]
    return "\n".join(lines) + "\n"


def render_dnsmasq(
    cfg: APConfig,
    iface: str,
    *,
    portal_ip: str,
    portal: bool,
    lease_file: str,
    pid_file: str,
    log_file: str,
) -> str:
    lines = [
        f"interface={iface}",
        "bind-interfaces",
        f"listen-address={portal_ip}",
        f"dhcp-range={cfg.dhcp_start},{cfg.dhcp_end},{cfg.lease_time}",
        f"dhcp-option=3,{portal_ip}",
        f"dhcp-option=6,{portal_ip}",
        "dhcp-authoritative",
        "domain-needed",
        "bogus-priv",
        "no-hosts",
        "cache-size=1000",
        f"pid-file={pid_file}",
        f"dhcp-leasefile={lease_file}",
        f"log-facility={log_file}",
        "user=root",
        "group=root",
    ]
    if portal and cfg.dns_hijack:
        lines += ["no-resolv", f"address=/#/{portal_ip}"]
    else:
        lines += ["no-resolv", f"server={cfg.upstream_dns}"]
    return "\n".join(lines) + "\n"


def render_nft(
    cfg: APConfig,
    *,
    ap_iface: str,
    uplink_iface: str | None,
    portal: bool,
    http_port: int,
    https_port: int,
    isolation: bool,
) -> str:
    network = str(ipaddress.ip_interface(cfg.subnet).network)
    lines = [
        "table inet kraken {",
        "  chain input {",
        "    type filter hook input priority filter; policy accept;",
        f'    iifname "{ap_iface}" udp dport 67 accept',
        f'    iifname "{ap_iface}" udp dport 53 accept',
    ]
    if portal:
        lines.append(
            f'    iifname "{ap_iface}" tcp dport {{ {http_port}, {https_port} }} accept'
        )
    lines += ["  }", "  chain forward {", "    type filter hook forward priority filter; policy accept;", "    ct state invalid drop"]
    if isolation:
        lines.append(f'    iifname "{ap_iface}" oifname "{ap_iface}" drop')
    if uplink_iface and uplink_iface != ap_iface:
        lines += [
            f'    iifname "{ap_iface}" oifname "{uplink_iface}" accept',
            f'    iifname "{uplink_iface}" oifname "{ap_iface}" ct state established,related accept',
        ]
    lines += ["  }"]
    if uplink_iface and uplink_iface != ap_iface:
        lines += [
            "  chain postrouting {",
            "    type nat hook postrouting priority srcnat; policy accept;",
            f'    oifname "{uplink_iface}" ip saddr {network} masquerade',
            "  }",
        ]
    if portal:
        lines += [
            "  chain prerouting {",
            "    type nat hook prerouting priority dstnat; policy accept;",
            f'    iifname "{ap_iface}" tcp dport 80 redirect to :{http_port}',
            f'    iifname "{ap_iface}" tcp dport 443 redirect to :{https_port}',
            "  }",
        ]
    lines += ["}"]
    return "\n".join(lines) + "\n"


class APServe:
    def __init__(self, cfg: APConfig, general: GeneralConfig, radio: RadioConfig):
        self.cfg = cfg
        self.general = general
        self.radio = radio
        self.iface = radio.ap_iface
        self.portal_ip = str(ipaddress.ip_interface(cfg.subnet).ip)
        self.run_dir = Path(general.run_dir)
        self.log_dir = Path(general.log_dir)
        self.hostapd_conf = self.run_dir / "hostapd.conf"
        self.dnsmasq_conf = self.run_dir / "dnsmasq.conf"
        self.lease_file = self.run_dir / "dnsmasq.leases"
        self.hostapd = ManagedProcess(
            "hostapd", ["hostapd", str(self.hostapd_conf)], self.log_dir / "hostapd.log"
        )
        self.dnsmasq = ManagedProcess(
            "dnsmasq",
            ["dnsmasq", "--keep-in-foreground", f"--conf-file={self.dnsmasq_conf}"],
            self.log_dir / "dnsmasq.log",
        )
        self.channel = cfg.channel
        self.band = cfg.band
        self.uplink: dict[str, Any] = {}
        self.started_at: float | None = None
        self.last_error = ""

    @property
    def running(self) -> bool:
        return self.hostapd.alive() and self.dnsmasq.alive()

    def start(self) -> None:
        self.iface = self.radio.ap_iface
        self.stop()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        rfkill_unblock_wifi()
        net.set_reg_domain(self.cfg.country or self.radio.reg_domain)
        net.nm_set_managed(self.iface, False)
        run_ok(["nmcli", "device", "disconnect", self.iface], timeout=5)
        net.link_down(self.iface)
        run_ok(["ip", "addr", "flush", "dev", self.iface], timeout=6)
        time.sleep(0.3)

        self.channel = self.cfg.channel
        self.band = self.cfg.band
        hw_mode = "a" if self.band == "5" else "g"
        if not self._try_hostapd(hw_mode=hw_mode, channel=self.channel):
            net.link_down(self.iface)
            time.sleep(0.4)
            if not self._try_hostapd(hw_mode=hw_mode, channel=self.channel):
                detail = "\n".join(tail_lines(self.log_dir / "hostapd.log", 8))
                _log.warning("hostapd failed to start on %s: %s", self.iface, detail)
                if self.cfg.fallback_2g and self.band == "5":
                    _log.warning("falling back to 2.4 GHz AP on channel 6")
                    self.band = "2.4"
                    self.channel = 6
                    net.link_down(self.iface)
                    time.sleep(0.3)
                    if not self._try_hostapd(hw_mode="g", channel=6):
                        self.last_error = "\n".join(tail_lines(self.log_dir / "hostapd.log", 12))
                        self.stop()
                        raise CommandError(f"hostapd cannot start on {self.iface}: {self.last_error}")
                else:
                    self.last_error = detail
                    self.stop()
                    raise CommandError(f"hostapd cannot start on {self.iface}: {detail}")

        run_ok(
            ["ip", "addr", "replace", f"{self.portal_ip}/24", "dev", self.iface],
            timeout=6,
        )
        net.link_up(self.iface)

        uplink = net.detect_uplink(
            self.radio.uplink_iface, exclude=(self.iface, self.radio.monitor_iface)
        )
        self.uplink = uplink if uplink.get("up") else {}
        net.set_ip_forward(True)

        self.dnsmasq_conf.write_text(
            render_dnsmasq(
                self.cfg,
                self.iface,
                portal_ip=self.portal_ip,
                portal=self.cfg.portal,
                lease_file=str(self.lease_file),
                pid_file=str(self.run_dir / "dnsmasq.pid"),
                log_file=str(self.log_dir / "dnsmasq.log"),
            ),
            encoding="utf-8",
        )
        test = run_ok(["dnsmasq", "--test", f"--conf-file={self.dnsmasq_conf}"], timeout=8)
        if not test:
            self.last_error = "\n".join(tail_lines(self.log_dir / "dnsmasq.log", 8))
            self.stop()
            raise CommandError(f"dnsmasq configuration rejected: {self.last_error}")
        self.dnsmasq.start()
        time.sleep(0.4)
        if not self.dnsmasq.alive():
            self.last_error = "\n".join(tail_lines(self.log_dir / "dnsmasq.log", 8))
            self.stop()
            raise CommandError(f"dnsmasq failed: {self.last_error}")
        if not self.hostapd.alive():
            self.last_error = "\n".join(tail_lines(self.log_dir / "hostapd.log", 12))
            self.stop()
            raise CommandError(f"hostapd exited on {self.iface}: {self.last_error}")

        rules = render_nft(
            self.cfg,
            ap_iface=self.iface,
            uplink_iface=self.uplink.get("iface"),
            portal=self.cfg.portal,
            http_port=self.general.http_port,
            https_port=self.general.https_port,
            isolation=self.cfg.client_isolation,
        )
        net.nft_apply(rules)
        self.last_error = ""
        self.started_at = time.time()
        _log.info(
            "AP up: ssid=%r iface=%s channel=%s portal=%s uplink=%s",
            self.cfg.ssid,
            self.iface,
            self.channel,
            self.cfg.portal,
            self.uplink.get("iface"),
        )

    def _try_hostapd(self, *, hw_mode: str, channel: int) -> bool:
        self.hostapd.stop()
        self.hostapd_conf.write_text(
            render_hostapd(self.cfg, self.iface, hw_mode=hw_mode, channel=channel),
            encoding="utf-8",
        )
        log_file = self.log_dir / "hostapd.log"
        try:
            offset = log_file.stat().st_size if log_file.exists() else 0
        except OSError:
            offset = 0
        self.hostapd.start()
        return self._wait_for_hostapd(offset=offset)

    def _wait_for_hostapd(self, *, offset: int = 0, timeout: float = 5.0) -> bool:
        log_file = self.log_dir / "hostapd.log"
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self.hostapd.alive():
                return False
            try:
                with log_file.open("rb") as handle:
                    handle.seek(offset)
                    chunk = handle.read().decode("utf-8", errors="replace")
            except OSError:
                chunk = ""
            if any(
                marker in chunk
                for marker in (
                    "AP-DISABLED",
                    "Unable to setup interface",
                    "Interface initialization failed",
                    "CTRL-EVENT-TERMINATING",
                )
            ):
                self.hostapd.stop(timeout=2)
                return False
            if "AP-ENABLED" in chunk:
                return True
            time.sleep(0.15)
        return self.hostapd.alive() and net.get_type(self.iface) == "AP"

    def stop(self) -> None:
        net.nft_clear()
        self.dnsmasq.stop()
        kill_stale(self.run_dir / "dnsmasq.pid")
        self.hostapd.stop()
        if net.iface_exists(self.iface):
            run_ok(["ip", "addr", "flush", "dev", self.iface], timeout=6)
            net.link_down(self.iface)
            net.set_type(self.iface, "managed")
            net.link_up(self.iface)
            if self.radio.restore_networkmanager:
                net.nm_set_managed(self.iface, True)
        self.uplink = {}
        self.started_at = None

    def reload(self) -> None:
        self.start()

    def clients(self) -> list[dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        for station in net.station_dump(self.iface):
            merged[station["mac"]] = {
                "mac": station["mac"],
                "rssi": station.get("rssi"),
                "rx_bytes": station.get("rx_bytes", 0),
                "tx_bytes": station.get("tx_bytes", 0),
                "connected_s": station.get("connected_s"),
                "ip": None,
                "hostname": "",
                "source": "wifi",
            }
        for lease in net.read_dhcp_leases(self.lease_file):
            entry = merged.setdefault(
                lease["mac"],
                {
                    "mac": lease["mac"],
                    "rssi": None,
                    "rx_bytes": 0,
                    "tx_bytes": 0,
                    "connected_s": None,
                    "source": "dhcp",
                },
            )
            entry["ip"] = lease["ip"]
            entry["hostname"] = lease["hostname"]
        return sorted(
            merged.values(),
            key=lambda item: (item.get("connected_s") or 0),
            reverse=True,
        )

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.running,
            "iface": self.iface,
            "ssid": self.cfg.ssid,
            "secured": bool(self.cfg.passphrase),
            "band": self.band,
            "channel": self.channel,
            "portal": self.cfg.portal,
            "portal_ip": self.portal_ip,
            "clients": self.clients() if self.running else [],
            "uplink": self.uplink,
            "started_at": self.started_at,
            "error": self.last_error,
        }
