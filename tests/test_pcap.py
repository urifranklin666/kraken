from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from kraken.pcap import (
    PcapngWriter,
    build_deauth,
    parse_frame,
    read_pcapng,
)
from tests import frames


class RadiotapParserTests(unittest.TestCase):
    def test_beacon_fields(self) -> None:
        frame = parse_frame(frames.beacon(), ts=1000.0)
        self.assertIsNotNone(frame)
        assert frame is not None
        self.assertTrue(frame.is_beacon)
        self.assertEqual(frame.bssid, "aa:bb:cc:dd:ee:01")
        self.assertEqual(frame.ssid, "LAB")
        self.assertEqual(frame.channel, 6)
        self.assertEqual(frame.rssi, -42)
        self.assertEqual(frame.privacy, "WPA2/3")

    def test_open_network(self) -> None:
        frame = parse_frame(frames.beacon(privacy=False), ts=1.0)
        assert frame is not None
        self.assertEqual(frame.privacy, "OPEN")

    def test_hidden_ssid(self) -> None:
        frame = parse_frame(frames.beacon(ssid=""), ts=1.0)
        assert frame is not None
        self.assertEqual(frame.ssid, "")

    def test_probe_request(self) -> None:
        frame = parse_frame(frames.probe_request(), ts=1.0)
        assert frame is not None
        self.assertTrue(frame.is_probe_req)
        self.assertIsNone(frame.bssid)
        self.assertEqual(frame.src, "aa:bb:cc:dd:ee:99")
        self.assertEqual(frame.ssid, "LAB")

    def test_malformed_returns_none(self) -> None:
        self.assertIsNone(parse_frame(b"", ts=1.0))
        self.assertIsNone(parse_frame(b"\x00" * 7, ts=1.0))
        self.assertIsNone(parse_frame(frames.radiotap() + b"\x00" * 3, ts=1.0))

    def test_eapol_m2(self) -> None:
        frame = parse_frame(frames.eapol_data(message=2), ts=1.0)
        assert frame is not None
        self.assertTrue(frame.is_data)
        self.assertEqual(frame.eapol_msg, 2)
        self.assertFalse(frame.pmkid)
        self.assertEqual(frame.bssid, "aa:bb:cc:dd:ee:01")
        self.assertEqual(frame.client, "aa:bb:cc:dd:ee:99")

    def test_pmkid_m1(self) -> None:
        frame = parse_frame(frames.eapol_data(message=1, pmkid=True), ts=1.0)
        assert frame is not None
        self.assertEqual(frame.eapol_msg, 1)
        self.assertTrue(frame.pmkid)

    def test_bad_fcs_ignored(self) -> None:
        frame = parse_frame(frames.beacon(), ts=1.0)
        assert frame is not None
        self.assertFalse(frame.bad_fcs)


class PcapngTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "capture.pcapng"
            packets = [frames.beacon(), frames.eapol_data()]
            with PcapngWriter(path, "wlan1") as writer:
                for index, packet in enumerate(packets):
                    writer.write(1000.0 + index, packet)
            self.assertGreater(path.stat().st_size, 32)
            result = list(read_pcapng(path))
            self.assertEqual(len(result), 2)
            self.assertAlmostEqual(result[0][0], 1000.0, places=5)
            self.assertEqual(result[0][1], packets[0])
            self.assertEqual(result[1][1], packets[1])

    def test_deauth_shape(self) -> None:
        packet = build_deauth("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:99")
        self.assertEqual(len(packet), 36)
        # radiotap header length
        self.assertEqual(packet[2] | (packet[3] << 8), 10)
        self.assertEqual(packet[10:12], b"\xc0\x00")


if __name__ == "__main__":
    unittest.main()
