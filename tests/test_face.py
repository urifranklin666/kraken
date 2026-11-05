from __future__ import annotations

import unittest

from kraken.capture import ChannelHopper
from kraken.face import compute_face


class FaceTests(unittest.TestCase):
    def test_idle_sleeps(self) -> None:
        face = compute_face(mode="idle", uptime=600)
        self.assertEqual(face.mood, "sleeping")
        self.assertIn("zZ", face.face)
        self.assertEqual(face.epoch, 2)

    def test_handshake_is_proud(self) -> None:
        face = compute_face(mode="recon", uptime=60, handshakes_recent=1)
        self.assertEqual(face.mood, "proud")

    def test_new_aps_are_exciting(self) -> None:
        face = compute_face(mode="hybrid", uptime=60, new_aps_recent=4)
        self.assertEqual(face.mood, "excited")

    def test_quiet_recon_is_bored(self) -> None:
        face = compute_face(
            mode="recon", uptime=3000, seconds_since_activity=1000, hops=50
        )
        self.assertEqual(face.mood, "bored")

    def test_recent_activity_is_focused(self) -> None:
        face = compute_face(
            mode="recon", uptime=60, seconds_since_activity=10, hops=5
        )
        self.assertEqual(face.mood, "focused")


class HopperTests(unittest.TestCase):
    def test_round_robin(self) -> None:
        hopper = ChannelHopper([1, 6, 11], adaptive=False)
        seen = [hopper.next() for _ in range(6)]
        self.assertEqual(seen, [1, 6, 11, 1, 6, 11])
        self.assertEqual(hopper.hops, 6)

    def test_adaptive_covers_all_channels(self) -> None:
        hopper = ChannelHopper([1, 6, 11], adaptive=True)
        seen = [hopper.next() for _ in range(30)]
        self.assertEqual(set(seen), {1, 6, 11})

    def test_adaptive_prefers_busy_channel(self) -> None:
        hopper = ChannelHopper([1, 6, 11], adaptive=True)
        for _ in range(4):
            hopper.record_ap(6)
        seen = [hopper.next() for _ in range(24)]
        self.assertGreater(seen.count(6), seen.count(1))
        self.assertGreater(seen.count(6), seen.count(11))


if __name__ == "__main__":
    unittest.main()
