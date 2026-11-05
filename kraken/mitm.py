"""Opt-in ARP/HTTP man-in-the-middle controller (bettercap).

Disabled unless the daemon was started with ``--authorized`` and
``[mitm].allow`` is true.  No credential extraction or TLS stripping is
configured; the caplet only demonstrates traffic interception on a lab
network you control.
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Any

from .config import APConfig, GeneralConfig, MitmConfig
from .util import CommandError, ManagedProcess, which, write_atomic

_CAPLET = """# KRAKEN MITM caplet — authorized lab use only.
set arp.spoof.fullduplex true
set arp.spoof.targets {subnet}
set net.sniff.verbose false
set http.proxy.port 8081
arp.spoof on
net.sniff on
http.proxy on
"""


class MitmController:
    def __init__(
        self,
        cfg: MitmConfig,
        ap_cfg: APConfig,
        general: GeneralConfig,
        *,
        ap_iface: str = "wlan0",
        authorized: bool = False,
    ):
        self.cfg = cfg
        self.ap_cfg = ap_cfg
        self.general = general
        self.ap_iface = ap_iface
        self.authorized = authorized
        self.run_dir = Path(general.run_dir)
        self.log_dir = Path(general.log_dir)
        self.caplet_path = self.run_dir / "kraken.caplet"
        self.process = ManagedProcess(
            "bettercap",
            ["bettercap", "-iface", ap_iface, "-caplet", str(self.caplet_path)],
            self.log_dir / "bettercap.log",
        )
        self.error = ""
        self._log = logging.getLogger("kraken.mitm")

    @property
    def installed(self) -> bool:
        return which("bettercap") is not None

    @property
    def available(self) -> bool:
        return bool(self.cfg.allow and self.installed)

    @property
    def running(self) -> bool:
        return self.process.alive()

    def start(self) -> None:
        if not self.cfg.allow:
            raise PermissionError("MITM is disabled in config ([mitm].allow = false)")
        if not self.authorized:
            raise PermissionError(
                "MITM requires the daemon to be started with --authorized "
                "on a network you own or have written permission to test"
            )
        if not self.installed:
            raise CommandError("bettercap is not installed")
        self.stop()
        network = str(ipaddress.ip_interface(self.ap_cfg.subnet).network)
        write_atomic(self.caplet_path, _CAPLET.format(subnet=network), mode=0o600)
        self.process.cmd = [
            "bettercap",
            "-iface",
            self.ap_iface,
            "-caplet",
            str(self.caplet_path),
        ]
        self.process.start()
        self.error = ""
        self._log.warning("MITM started on %s (authorized mode)", self.ap_iface)

    def stop(self) -> None:
        self.process.stop()
        self.error = ""

    def status(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "installed": self.installed,
            "authorized": self.authorized,
            "allowed": bool(self.cfg.allow),
            "enabled": self.running,
            "error": self.error,
        }
