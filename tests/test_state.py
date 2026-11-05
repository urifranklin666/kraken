from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from kraken.state import Store


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "kraken.db")

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    def test_ap_upsert_and_counts(self) -> None:
        self.store.upsert_ap("aa:bb:cc:dd:ee:01", "LAB", 6, -40, "WPA2", ts=100)
        self.store.upsert_ap("aa:bb:cc:dd:ee:01", "", 6, -50, "WPA2", ts=101)
        rows = self.store.aps()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ssid"], "LAB")
        self.assertEqual(rows[0]["beacons"], 2)
        self.assertEqual(rows[0]["rssi"], -50)
        counts = self.store.counts()
        self.assertEqual(counts["aps"], 1)

    def test_client_upsert(self) -> None:
        self.store.upsert_client("aa:bb:cc:dd:ee:99", "aa:bb:cc:dd:ee:01", -55)
        self.store.upsert_client("aa:bb:cc:dd:ee:99", "aa:bb:cc:dd:ee:01", -60)
        rows = self.store.clients()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["rssi"], -60)
        self.assertEqual(self.store.counts()["clients"], 1)

    def test_handshake_cooldown_and_verify(self) -> None:
        first = self.store.add_handshake(
            bssid="aa:bb:cc:dd:ee:01",
            ssid="LAB",
            kind="eapol",
            path="/tmp/x.pcapng",
            size=100,
            ts=1000,
            cooldown=30,
        )
        self.assertIsNotNone(first)
        second = self.store.add_handshake(
            bssid="aa:bb:cc:dd:ee:01",
            ssid="LAB",
            kind="eapol",
            path="/tmp/x.pcapng",
            size=200,
            ts=1010,
            cooldown=30,
        )
        self.assertIsNone(second)
        third = self.store.add_handshake(
            bssid="aa:bb:cc:dd:ee:01",
            ssid="LAB",
            kind="eapol",
            path="/tmp/x.pcapng",
            size=300,
            ts=1100,
            cooldown=30,
        )
        self.assertIsNotNone(third)
        self.store.mark_verified(int(first), True, "2 hashes")
        assert third is not None
        row = self.store.handshake(int(third))
        assert row is not None
        self.assertEqual(row["verified"], 0)
        verified = [row for row in self.store.handshakes() if row["verified"]]
        self.assertEqual(len(verified), 1)

    def test_settings_and_events(self) -> None:
        self.assertIsNone(self.store.get_setting("missing"))
        self.store.set_setting("ap.ssid", "NEW")
        self.assertEqual(self.store.get_setting("ap.ssid"), "NEW")
        self.store.add_event("info", "test", "hello")
        events = self.store.events()
        self.assertEqual(events[-1]["message"], "hello")

    def test_session(self) -> None:
        session = self.store.start_session("recon")
        self.assertGreater(session, 0)
        self.store.end_session(session, aps=3, clients=2, handshakes=1, hops=10)


if __name__ == "__main__":
    unittest.main()
