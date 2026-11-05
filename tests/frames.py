"""Synthetic radiotap/802.11 frames for parser tests."""

from __future__ import annotations

import struct

BROADCAST = "ff:ff:ff:ff:ff:ff"


def mac(value: str) -> bytes:
    return bytes.fromhex(value.replace(":", ""))


def radiotap(freq: int = 2437, rssi: int = -42, flags: int = 0) -> bytes:
    present = (1 << 1) | (1 << 3) | (1 << 5)
    header = struct.pack("<BBHI", 0, 0, 15, present)
    header += bytes([flags])  # bit 1: flags
    header += b"\x00"  # padding for the 2-byte-aligned channel field
    header += struct.pack("<HH", freq, 0)  # bit 3: channel
    header += struct.pack("<b", rssi)  # bit 5: signal
    assert len(header) == 15
    return header


def ie(element_id: int, body: bytes) -> bytes:
    return bytes([element_id, len(body)]) + body


def beacon(
    ssid: str = "LAB",
    bssid: str = "aa:bb:cc:dd:ee:01",
    channel: int = 6,
    *,
    privacy: bool = True,
    rssi: int = -42,
    freq: int | None = None,
) -> bytes:
    ssid_bytes = ssid.encode("utf-8")
    capability = 0x0010 if privacy else 0x0001
    frame = struct.pack("<HH", 0x0080, 0)
    frame += mac(BROADCAST) + mac(bssid) + mac(bssid) + struct.pack("<H", 0)
    frame += b"\x00" * 8 + struct.pack("<HH", 100, capability)
    frame += ie(0, ssid_bytes)
    frame += ie(3, bytes([channel]))
    if privacy:
        frame += ie(48, b"\x01\x00")
    return radiotap(freq or (2407 + 5 * channel), rssi) + frame


def probe_request(ssid: str = "LAB", client: str = "aa:bb:cc:dd:ee:99", channel: int = 6) -> bytes:
    frame = struct.pack("<HH", 0x0040, 0)
    frame += mac(BROADCAST) + mac(client) + mac(BROADCAST) + struct.pack("<H", 0)
    frame += ie(0, ssid.encode("utf-8")) + ie(3, bytes([channel]))
    return radiotap(2407 + 5 * channel, -60) + frame


def _key_info(message: int) -> int:
    # descriptor version 2 in the low three bits
    if message == 1:
        return 0x0042  # ACK
    if message == 2:
        return 0x0082  # MIC
    if message == 3:
        return 0x00E2  # ACK | MIC | INSTALL
    return 0x0182  # MIC | SECURE


def eapol_data(
    bssid: str = "aa:bb:cc:dd:ee:01",
    client: str = "aa:bb:cc:dd:ee:99",
    message: int = 2,
    *,
    pmkid: bool = False,
) -> bytes:
    frame = struct.pack("<HH", 0x0208, 0)  # data, FromDS
    frame += mac(client) + mac(bssid) + mac(bssid) + struct.pack("<H", 0)
    frame += b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
    key_data = b""
    if pmkid:
        key_data = b"\xdd\x14\x00\x0f\xac\x04" + bytes(range(16))
    descriptor = bytes([2])  # descriptor type: RSN
    descriptor += struct.pack(">H", _key_info(message))
    descriptor += struct.pack(">H", 16)  # key length
    descriptor += b"\x00" * 8  # replay
    descriptor += b"\x11" * 32  # nonce
    descriptor += b"\x22" * 16  # IV
    descriptor += b"\x00" * 8  # RSC
    descriptor += b"\x00" * 8  # key ID
    descriptor += b"\x33" * 16  # MIC
    descriptor += struct.pack(">H", len(key_data)) + key_data
    eapol = bytes([2, 3]) + struct.pack(">H", len(descriptor)) + descriptor
    return radiotap(2437, -40) + frame + eapol
