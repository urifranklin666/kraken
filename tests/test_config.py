from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from kraken.config import Config, ConfigError


class ConfigTests(unittest.TestCase):
    def test_defaults_are_valid(self) -> None:
        cfg = Config()
        cfg.validate()
        self.assertEqual(cfg.portal_ip, "10.13.37.1")
        self.assertEqual(cfg.subnet_cidr, "10.13.37.0/24")

    def test_load_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kraken.toml"
            path.write_text(
                """
[general]
default_mode = "recon"
http_port = 9090

[radio]
monitor_iface = "mon0"
ap_iface = "wlan9"

[recon]
channels = [1, 6, 11]
aggressive = true

[ap]
ssid = "LAB"
passphrase = "correct horse battery"
channel = 44
band = "5"

[mitm]
allow = false
""",
                encoding="utf-8",
            )
            cfg = Config.load(str(path))
            self.assertEqual(cfg.general.default_mode, "recon")
            self.assertEqual(cfg.general.http_port, 9090)
            self.assertEqual(cfg.radio.monitor_iface, "mon0")
            self.assertEqual(cfg.recon.channels, [1, 6, 11])
            self.assertTrue(cfg.recon.aggressive)
            self.assertEqual(cfg.ap.ssid, "LAB")
            self.assertFalse(cfg.mitm.allow)
            public = cfg.as_public_dict()
            self.assertNotIn("passphrase", public["ap"])
            self.assertTrue(public["ap"]["secured"])

    def test_invalid_values_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kraken.toml"
            cases = [
                '[radio]\nmonitor_iface = "wlan1"\nap_iface = "wlan1"\n',
                '[ap]\nssid = ""\n',
                '[ap]\npassphrase = "short"\n',
                '[ap]\nchannel = 6\nband = "5"\n',
                '[recon]\nchannels = []\n',
                '[recon]\nchannels = [0]\n',
                '[general]\ndefault_mode = "turbo"\n',
                '[recon]\nwhitelist = ["nope"]\n',
                '[unknown]\nthing = 1\n',
            ]
            for text in cases:
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(ConfigError, msg=text):
                    Config.load(str(path))

    def test_missing_file_is_default(self) -> None:
        cfg = Config.load("/nonexistent/kraken.toml")
        self.assertEqual(cfg.general.default_mode, "hybrid")


if __name__ == "__main__":
    unittest.main()
