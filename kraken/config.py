"""Configuration loading and validation for KRAKEN."""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .util import is_iface


class ConfigError(ValueError):
    pass


VALID_MODES = ("hybrid", "recon", "ap", "idle")


def _default_channels() -> list[int]:
    # Weighted toward the three non-overlapping 2.4 GHz channels.
    return [1, 6, 11, 1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13]


@dataclass
class GeneralConfig:
    hostname: str = "kraken"
    data_dir: str = "/var/lib/kraken"
    run_dir: str = "/run/kraken"
    log_dir: str = "/var/log/kraken"
    token_file: str = "/etc/kraken/api.token"
    cert_file: str = "/etc/kraken/tls/cert.pem"
    key_file: str = "/etc/kraken/tls/key.pem"
    assets_dir: str = "/opt/kraken/app/kraken/assets"
    http_port: int = 8080
    https_port: int = 8443
    bind: str = "0.0.0.0"
    default_mode: str = "hybrid"
    open_read: bool = False
    authorized: bool = False


@dataclass
class RadioConfig:
    monitor_iface: str = "wlan1"
    ap_iface: str = "wlan0"
    uplink_iface: str = "auto"
    reg_domain: str = "US"
    restore_networkmanager: bool = True


@dataclass
class ReconConfig:
    channels: list[int] = field(default_factory=_default_channels)
    hop_interval: float = 1.2
    adaptive_hop: bool = True
    aggressive: bool = False
    deauth_burst: int = 2
    deauth_cooldown: float = 10.0
    max_capture_mb: int = 4096
    max_capture_files: int = 120
    max_total_mb: int = 20480
    handshake_cooldown: float = 30.0
    whitelist: list[str] = field(default_factory=list)
    blacklist: list[str] = field(default_factory=list)
    verify_with_hcxtools: bool = True


@dataclass
class APConfig:
    ssid: str = "KRAKEN//LAB"
    passphrase: str = ""
    channel: int = 36
    band: str = "5"  # "5" or "2.4"
    portal: bool = True
    dns_hijack: bool = True
    client_isolation: bool = True
    fallback_2g: bool = True
    subnet: str = "10.13.37.1/24"
    dhcp_start: str = "10.13.37.100"
    dhcp_end: str = "10.13.37.200"
    lease_time: str = "12h"
    country: str = "US"
    max_clients: int = 32
    upstream_dns: str = "1.1.1.1"


@dataclass
class MitmConfig:
    allow: bool = True
    auto_start: bool = False


@dataclass
class Config:
    general: GeneralConfig = field(default_factory=GeneralConfig)
    radio: RadioConfig = field(default_factory=RadioConfig)
    recon: ReconConfig = field(default_factory=ReconConfig)
    ap: APConfig = field(default_factory=APConfig)
    mitm: MitmConfig = field(default_factory=MitmConfig)
    source: str = "defaults"

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        cfg = cls()
        if not path:
            return cfg
        file = Path(path)
        if not file.exists():
            return cfg
        try:
            data = tomllib.loads(file.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"cannot read {file}: {exc}") from exc
        unknown = set(data) - {"general", "radio", "recon", "ap", "mitm"}
        if unknown:
            raise ConfigError(f"unknown config section(s): {', '.join(sorted(unknown))}")
        _apply(cfg.general, data.get("general", {}), "general")
        _apply(cfg.radio, data.get("radio", {}), "radio")
        _apply(cfg.recon, data.get("recon", {}), "recon")
        _apply(cfg.ap, data.get("ap", {}), "ap")
        _apply(cfg.mitm, data.get("mitm", {}), "mitm")
        cfg.source = str(file)
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if self.general.default_mode not in VALID_MODES:
            raise ConfigError(f"general.default_mode must be one of {VALID_MODES}")
        for name in ("monitor_iface", "ap_iface"):
            if not is_iface(getattr(self.radio, name)):
                raise ConfigError(f"radio.{name} is not a valid interface name")
        if self.radio.ap_iface == self.radio.monitor_iface:
            raise ConfigError("radio.ap_iface and radio.monitor_iface must differ")
        if self.radio.uplink_iface != "auto" and not is_iface(self.radio.uplink_iface):
            raise ConfigError("radio.uplink_iface must be 'auto' or an interface name")
        if not self.recon.channels:
            raise ConfigError("recon.channels must not be empty")
        for channel in self.recon.channels:
            if not isinstance(channel, int) or not 1 <= channel <= 165:
                raise ConfigError("recon.channels must be integers between 1 and 165")
        if not 0.2 <= float(self.recon.hop_interval) <= 30:
            raise ConfigError("recon.hop_interval must be between 0.2 and 30 seconds")
        if not 32 <= int(self.recon.max_capture_mb) <= 262144:
            raise ConfigError("recon.max_capture_mb out of range")
        if not 8 <= int(self.recon.max_capture_files) <= 10000:
            raise ConfigError("recon.max_capture_files out of range")
        if not int(self.recon.max_capture_mb) <= int(self.recon.max_total_mb) <= 1048576:
            raise ConfigError("recon.max_total_mb must be >= max_capture_mb")
        if not self.ap.ssid or len(self.ap.ssid.encode("utf-8")) > 32:
            raise ConfigError("ap.ssid must be 1-32 UTF-8 bytes")
        if any(ord(ch) < 32 for ch in self.ap.ssid):
            raise ConfigError("ap.ssid must not contain control characters")
        passphrase = self.ap.passphrase
        if passphrase and not (8 <= len(passphrase) <= 63):
            raise ConfigError("ap.passphrase must be empty (open) or 8-63 characters")
        if any(ord(ch) < 32 for ch in passphrase):
            raise ConfigError("ap.passphrase must not contain control characters")
        if self.ap.band not in ("5", "2.4"):
            raise ConfigError("ap.band must be '5' or '2.4'")
        if self.ap.band == "5" and self.ap.channel not in range(36, 166):
            raise ConfigError("ap.channel must be a 5 GHz channel (36-165) when band='5'")
        if self.ap.band == "2.4" and self.ap.channel not in range(1, 14):
            raise ConfigError("ap.channel must be a 2.4 GHz channel (1-13) when band='2.4'")
        try:
            net = ipaddress.ip_interface(self.ap.subnet)
            dhcp_start = ipaddress.ip_address(self.ap.dhcp_start)
            dhcp_end = ipaddress.ip_address(self.ap.dhcp_end)
        except ValueError as exc:
            raise ConfigError(f"invalid AP network: {exc}") from exc
        if net.version != 4:
            raise ConfigError("ap.subnet must be IPv4")
        if net.network.prefixlen > 29:
            raise ConfigError("ap.subnet prefix must be /29 or larger")
        if dhcp_start not in net.network or dhcp_end not in net.network:
            raise ConfigError("DHCP range must be inside ap.subnet")
        if int(dhcp_start) > int(dhcp_end):
            raise ConfigError("dhcp_start must be <= dhcp_end")
        if not 1024 <= int(self.general.http_port) <= 65535:
            raise ConfigError("general.http_port out of range")
        if not 1024 <= int(self.general.https_port) <= 65535:
            raise ConfigError("general.https_port out of range")
        if self.general.http_port == self.general.https_port:
            raise ConfigError("HTTP and HTTPS ports must differ")
        for addr in self.recon.whitelist + self.recon.blacklist:
            if not _looks_like_mac(addr):
                raise ConfigError(f"invalid MAC in recon whitelist/blacklist: {addr}")

    @property
    def portal_ip(self) -> str:
        return str(ipaddress.ip_interface(self.ap.subnet).ip)

    @property
    def subnet_cidr(self) -> str:
        return str(ipaddress.ip_interface(self.ap.subnet).network)

    def as_public_dict(self) -> dict[str, Any]:
        """Configuration safe to expose through the API (no secrets)."""
        return {
            "general": {
                "hostname": self.general.hostname,
                "default_mode": self.general.default_mode,
                "http_port": self.general.http_port,
                "https_port": self.general.https_port,
                "open_read": self.general.open_read,
            },
            "radio": {
                "monitor_iface": self.radio.monitor_iface,
                "ap_iface": self.radio.ap_iface,
                "uplink_iface": self.radio.uplink_iface,
                "reg_domain": self.radio.reg_domain,
            },
            "recon": {
                "channels": list(self.recon.channels),
                "hop_interval": self.recon.hop_interval,
                "adaptive_hop": self.recon.adaptive_hop,
                "aggressive": self.recon.aggressive,
                "max_capture_mb": self.recon.max_capture_mb,
                "max_total_mb": self.recon.max_total_mb,
            },
            "ap": {
                "ssid": self.ap.ssid,
                "secured": bool(self.ap.passphrase),
                "band": self.ap.band,
                "channel": self.ap.channel,
                "portal": self.ap.portal,
                "client_isolation": self.ap.client_isolation,
                "subnet": self.ap.subnet,
            },
            "mitm": {"allow": self.mitm.allow, "auto_start": self.mitm.auto_start},
        }


def _apply(target: object, data: dict[str, Any], section: str) -> None:
    if not isinstance(data, dict):
        raise ConfigError(f"[{section}] must be a table")
    allowed = {f.name for f in fields(target)}  # type: ignore[arg-type]
    for key, value in data.items():
        if key not in allowed:
            raise ConfigError(f"unknown key in [{section}]: {key}")
        current = getattr(target, key)
        if isinstance(current, bool) and not isinstance(value, bool):
            raise ConfigError(f"[{section}].{key} must be a boolean")
        if isinstance(current, int) and not isinstance(current, bool) and not isinstance(value, int):
            raise ConfigError(f"[{section}].{key} must be an integer")
        if isinstance(current, float) and not isinstance(value, (int, float)):
            raise ConfigError(f"[{section}].{key} must be a number")
        if isinstance(current, list) and not isinstance(value, list):
            raise ConfigError(f"[{section}].{key} must be a list")
        setattr(target, key, value)


def _looks_like_mac(value: str) -> bool:
    parts = value.lower().split(":")
    return len(parts) == 6 and all(len(p) == 2 and all(c in "0123456789abcdef" for c in p) for p in parts)
