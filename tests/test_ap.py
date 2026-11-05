from __future__ import annotations

import unittest

from kraken.ap import render_dnsmasq, render_hostapd, render_nft
from kraken.config import APConfig


class RenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = APConfig(ssid="KRAKEN//LAB", passphrase="", channel=36, band="5")

    def test_hostapd_5g_open(self) -> None:
        text = render_hostapd(self.cfg, "wlan0")
        self.assertIn("interface=wlan0", text)
        self.assertIn("hw_mode=a", text)
        self.assertIn("channel=36", text)
        self.assertIn("ssid=KRAKEN//LAB", text)
        self.assertIn("ap_isolate=1", text)
        self.assertNotIn("wpa=2", text)

    def test_hostapd_wpa2(self) -> None:
        self.cfg.passphrase = "correct horse battery"
        text = render_hostapd(self.cfg, "wlan0")
        self.assertIn("wpa=2", text)
        self.assertIn("wpa_key_mgmt=WPA-PSK", text)
        self.assertIn("rsn_pairwise=CCMP", text)

    def test_dnsmasq_portal(self) -> None:
        text = render_dnsmasq(
            self.cfg,
            "wlan0",
            portal_ip="10.13.37.1",
            portal=True,
            lease_file="/run/x.leases",
            pid_file="/run/x.pid",
            log_file="/tmp/x.log",
        )
        self.assertIn("address=/#/10.13.37.1", text)
        self.assertIn("dhcp-range=10.13.37.100,10.13.37.200,12h", text)
        self.assertIn("no-resolv", text)

    def test_dnsmasq_no_portal(self) -> None:
        text = render_dnsmasq(
            self.cfg,
            "wlan0",
            portal_ip="10.13.37.1",
            portal=False,
            lease_file="/run/x.leases",
            pid_file="/run/x.pid",
            log_file="/tmp/x.log",
        )
        self.assertNotIn("address=/#/", text)
        self.assertIn("server=1.1.1.1", text)

    def test_nft_rules(self) -> None:
        text = render_nft(
            self.cfg,
            ap_iface="wlan0",
            uplink_iface="eth0",
            portal=True,
            http_port=8080,
            https_port=8443,
            isolation=True,
        )
        self.assertIn("masquerade", text)
        self.assertIn("redirect to :8080", text)
        self.assertIn("redirect to :8443", text)
        self.assertIn('iifname "wlan0" oifname "wlan0" drop', text)
        self.assertIn("10.13.37.0/24", text)

    def test_nft_without_uplink(self) -> None:
        text = render_nft(
            self.cfg,
            ap_iface="wlan0",
            uplink_iface=None,
            portal=False,
            http_port=8080,
            https_port=8443,
            isolation=False,
        )
        self.assertNotIn("masquerade", text)
        self.assertNotIn("prerouting", text)


if __name__ == "__main__":
    unittest.main()
