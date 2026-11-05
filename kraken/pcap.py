"""802.11 monitor-mode capture primitives.

This module is deliberately self-contained: it writes pcapng (readable by
hcxtools/Wireshark), parses radiotap + 802.11 management/data frames, detects
EAPOL handshake messages and PMKID KDEs, and can build deauthentication frames.

No third-party packages are required.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

LINKTYPE_IEEE802_11_RADIOTAP = 127
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_EPB = 0x00000006
BYTE_ORDER_MAGIC = 0x1A2B3C4D

_BROADCAST = "ff:ff:ff:ff:ff:ff"

# Radiotap field: index -> (alignment, size).  Bits 28+ are variable/namespace
# fields; parsing stops there because channel and signal (bits 3 and 5) are
# always earlier in the bitmap.
_RT_FIELDS: dict[int, tuple[int, int]] = {
    0: (8, 8),   # TSFT
    1: (1, 1),   # flags
    2: (1, 1),   # rate
    3: (2, 4),   # channel (freq, flags)
    4: (2, 2),   # FHSS
    5: (1, 1),   # dBm antenna signal
    6: (1, 1),   # antenna
    7: (1, 1),   # dBm antenna noise
    8: (2, 2),   # lock quality
    9: (2, 2),   # TX attenuation
    10: (2, 2),  # dB TX attenuation
    11: (1, 1),  # dBm TX power
    12: (1, 1),  # antenna
    13: (1, 1),  # dB antenna signal
    14: (1, 1),  # dB antenna noise
    15: (2, 2),  # RX flags
    16: (2, 2),  # TX flags
    17: (1, 1),  # RTS retries
    18: (1, 1),  # data retries
    19: (4, 8),  # XChannel
    20: (1, 3),  # MCS
    21: (4, 8),  # AMPDU status
    22: (2, 12), # VHT
    23: (8, 12), # timestamp
    24: (2, 12), # HE
    25: (2, 12), # HE-MU
    26: (1, 0),  # 0-length PSDU
    27: (2, 4),  # L-SIG
}


@dataclass(frozen=True)
class Radiotap:
    length: int
    freq: int | None
    channel: int | None
    rssi: int | None
    flags: int

    @property
    def bad_fcs(self) -> bool:
        return bool(self.flags & 0x40)

    @property
    def has_fcs(self) -> bool:
        return bool(self.flags & 0x10)


@dataclass(frozen=True)
class Frame:
    ts: float
    iface: str
    length: int
    ftype: int
    subtype: int
    bssid: str | None
    src: str | None
    dst: str | None
    ssid: str | None
    channel: int | None
    rssi: int | None
    privacy: str | None
    eapol_msg: int | None
    pmkid: bool
    bad_fcs: bool
    to_ds: bool = False
    from_ds: bool = False

    @property
    def is_beacon(self) -> bool:
        return self.ftype == 0 and self.subtype == 8

    @property
    def is_probe_resp(self) -> bool:
        return self.ftype == 0 and self.subtype == 5

    @property
    def is_probe_req(self) -> bool:
        return self.ftype == 0 and self.subtype == 4

    @property
    def is_data(self) -> bool:
        return self.ftype == 2

    @property
    def has_eapol(self) -> bool:
        return self.eapol_msg is not None

    @property
    def client(self) -> str | None:
        """Best-effort associated/unassociated client for this frame."""
        if self.ftype != 2:
            return self.src if self.src and self.src != self.bssid else None
        return self.src if self.to_ds else self.dst


def freq_to_channel(freq: int | None) -> int | None:
    if not freq:
        return None
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 2484 == freq:
        return 14
    if 5000 <= freq <= 5895:
        return (freq - 5000) // 5
    return None


def mac_to_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


def bytes_to_mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def parse_radiotap(buf: bytes) -> tuple[Radiotap, bytes] | None:
    if len(buf) < 8 or buf[0] != 0:
        return None
    it_len = struct.unpack_from("<H", buf, 2)[0]
    if it_len < 8 or it_len > len(buf):
        return None

    words: list[int] = []
    offset = 4
    while True:
        if offset + 4 > it_len or len(words) >= 4:
            return None
        word = struct.unpack_from("<I", buf, offset)[0]
        offset += 4
        words.append(word)
        if not word & 0x80000000:
            break

    flags = 0
    freq: int | None = None
    rssi: int | None = None
    offset = 4 + 4 * len(words)

    for index in range(32 * len(words)):
        if not (words[index // 32] >> (index % 32)) & 1:
            continue
        if index == 31:
            continue
        if index >= 28:
            # Variable-length namespace/TLV/vendor fields.  Everything we
            # need appears before them.
            break
        spec = _RT_FIELDS.get(index)
        if spec is None:
            return None
        align, size = spec
        offset = (offset + align - 1) & ~(align - 1)
        if offset + size > it_len:
            return None
        if index == 1:
            flags = buf[offset]
        elif index == 3:
            freq = struct.unpack_from("<H", buf, offset)[0]
        elif index == 5:
            rssi = struct.unpack_from("<b", buf, offset)[0]
        elif index == 13 and rssi is None:
            rssi = struct.unpack_from("<b", buf, offset)[0]
        offset += size

    payload = buf[it_len:]
    if flags & 0x10 and len(payload) >= 4:
        payload = payload[:-4]
    return Radiotap(it_len, freq, freq_to_channel(freq), rssi, flags), payload


def parse_ies(data: bytes) -> dict[int, list[bytes]]:
    ies: dict[int, list[bytes]] = {}
    offset = 0
    while offset + 2 <= len(data):
        element_id = data[offset]
        length = data[offset + 1]
        offset += 2
        if offset + length > len(data):
            break
        ies.setdefault(element_id, []).append(data[offset : offset + length])
        offset += length
    return ies


def _decode_ssid(value: bytes | None) -> str:
    if not value:
        return ""
    value = value.split(b"\x00", 1)[0]
    return value.decode("utf-8", errors="replace").strip()


def _security(capability: int, ies: dict[int, list[bytes]]) -> str:
    rsn = 48 in ies
    wpa = any(
        len(value) >= 4 and value[:4] == b"\x00\x50\xf2\x01"
        for value in ies.get(221, [])
    )
    if rsn and wpa:
        return "WPA2"
    if rsn:
        return "WPA2/3"
    if wpa:
        return "WPA"
    if capability & 0x0010:
        return "WEP"
    return "OPEN"


def parse_eapol(payload: bytes, offset: int) -> tuple[int | None, bool]:
    """Return (EAPOL-Key message number, PMKID present)."""
    if payload[offset : offset + 8] != b"\xaa\xaa\x03\x00\x00\x00\x88\x8e":
        return None, False
    start = offset + 8
    if len(payload) < start + 99:
        return None, False
    if payload[start + 1] != 3:  # EAPOL-Key
        return None, False
    key_info = struct.unpack_from(">H", payload, start + 5)[0]
    ack = bool(key_info & 0x0040)
    mic = bool(key_info & 0x0080)
    install = bool(key_info & 0x0020)
    secure = bool(key_info & 0x0100)
    if ack and not mic:
        message = 1
    elif mic and not ack and not install and not secure:
        message = 2
    elif ack and mic and install:
        message = 3
    elif mic and not ack and secure:
        message = 4
    else:
        message = None

    key_data_len = struct.unpack_from(">H", payload, start + 97)[0]
    key_data = payload[start + 99 : start + 99 + key_data_len]
    pmkid = b"\xdd\x14\x00\x0f\xac\x04" in key_data
    return message, pmkid


def parse_frame(raw: bytes, *, ts: float, iface: str = "wlan1") -> Frame | None:
    parsed = parse_radiotap(raw)
    if parsed is None:
        return None
    radio, payload = parsed
    if radio.bad_fcs or len(payload) < 10:
        return None

    fc = struct.unpack_from("<H", payload, 0)[0]
    version = fc & 0x0003
    if version != 0:
        return None
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    frame_flags = (fc >> 8) & 0xFF

    header_len = 24 + (4 if frame_flags & 0x80 else 0)
    if len(payload) < header_len:
        return None
    addr1 = bytes_to_mac(payload[4:10])
    addr2 = bytes_to_mac(payload[10:16])
    addr3 = bytes_to_mac(payload[16:22])

    bssid: str | None = addr3
    src: str | None = addr2
    dst: str | None = addr1
    ssid: str | None = None
    privacy: str | None = None
    eapol_msg: int | None = None
    pmkid = False
    body = header_len
    to_ds = False
    from_ds = False

    if ftype == 0:  # management
        if subtype in (8, 5):  # beacon, probe response
            if len(payload) < body + 12:
                return None
            capability = struct.unpack_from("<H", payload, body + 10)[0]
            ies = parse_ies(payload[body + 12 :])
            ssid = _decode_ssid((ies.get(0) or [b""])[0])
            privacy = _security(capability, ies)
        elif subtype == 4:  # probe request
            ies = parse_ies(payload[body:])
            ssid = _decode_ssid((ies.get(0) or [b""])[0])
            bssid = None
            dst = _BROADCAST if addr1 == _BROADCAST else addr1
        elif subtype == 0:  # association request
            if len(payload) < body + 4:
                return None
            ies = parse_ies(payload[body + 4 :])
            ssid = _decode_ssid((ies.get(0) or [b""])[0])
            bssid = addr1
        elif subtype == 11:  # authentication
            bssid = addr1
    elif ftype == 2:  # data
        to_ds = bool(frame_flags & 0x01)
        from_ds = bool(frame_flags & 0x02)
        if to_ds and from_ds:
            header_len += 6
            if len(payload) < header_len:
                return None
            addr4 = bytes_to_mac(payload[24:30])
            bssid = addr1
            src = addr4
            dst = addr3
        elif to_ds:
            bssid = addr1
            src = addr2
            dst = addr3
        elif from_ds:
            bssid = addr2
            src = addr3
            dst = addr1
        else:
            bssid = addr3
            src = addr2
            dst = addr1
        if subtype & 0x08:  # QoS data
            header_len += 2
        body = header_len
        if len(payload) >= body + 8:
            eapol_msg, pmkid = parse_eapol(payload, body)
    else:
        return None

    channel = radio.channel
    if ftype == 0 and subtype in (8, 5):
        ies = parse_ies(payload[body + 12 :])
        ds = ies.get(3)
        if ds and len(ds[0]) >= 1:
            channel = ds[0][0]
    elif ftype == 0 and subtype == 4:
        ies = parse_ies(payload[body:])
        ds = ies.get(3)
        if ds and len(ds[0]) >= 1:
            channel = ds[0][0]

    return Frame(
        ts=ts,
        iface=iface,
        length=len(raw),
        ftype=ftype,
        subtype=subtype,
        bssid=bssid,
        src=src,
        dst=dst,
        ssid=ssid,
        channel=channel,
        rssi=radio.rssi,
        privacy=privacy,
        eapol_msg=eapol_msg,
        pmkid=pmkid,
        bad_fcs=radio.bad_fcs,
        to_ds=to_ds,
        from_ds=from_ds,
    )


class PcapngWriter:
    """Append-only pcapng writer (one interface, radiotap link type)."""

    def __init__(self, path: str | Path, iface: str, app: str = "KRAKEN 1.0.0"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("wb", buffering=1024 * 256)
        self.size = 0
        self._write_block(self._shb(app))
        self._write_block(self._idb(iface))
        self.flush()

    @staticmethod
    def _option(code: int, value: bytes) -> bytes:
        padding = (-len(value)) % 4
        return struct.pack("<HH", code, len(value)) + value + b"\x00" * padding

    def _shb(self, app: str) -> bytes:
        options = self._option(4, app.encode("utf-8")) + struct.pack("<HH", 0, 0)
        body = struct.pack("<IHHq", BYTE_ORDER_MAGIC, 1, 0, -1) + options
        return self._block(PCAPNG_SHB, body)

    def _idb(self, iface: str) -> bytes:
        options = self._option(2, iface.encode("utf-8")) + self._option(9, b"\x06")
        options += struct.pack("<HH", 0, 0)
        body = struct.pack("<HHI", LINKTYPE_IEEE802_11_RADIOTAP, 0, 65535) + options
        return self._block(PCAPNG_IDB, body)

    @staticmethod
    def _block(block_type: int, body: bytes) -> bytes:
        body += b"\x00" * ((-len(body)) % 4)
        total = 12 + len(body)
        return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)

    def _write_block(self, block: bytes) -> None:
        self._handle.write(block)
        self.size += len(block)

    def write(self, ts: float, data: bytes) -> None:
        microseconds = int(ts * 1_000_000)
        timestamp_high = (microseconds >> 32) & 0xFFFFFFFF
        timestamp_low = microseconds & 0xFFFFFFFF
        body = struct.pack(
            "<IIIII",
            0,
            timestamp_high,
            timestamp_low,
            len(data),
            len(data),
        )
        body += data + b"\x00" * ((-len(data)) % 4)
        body += struct.pack("<HH", 0, 0)
        self._write_block(self._block(PCAPNG_EPB, body))

    def flush(self) -> None:
        try:
            self._handle.flush()
        except OSError:
            pass

    def close(self) -> None:
        if self._handle.closed:
            return
        try:
            self.flush()
            self._handle.close()
        except OSError:
            pass

    def __enter__(self) -> "PcapngWriter":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def read_pcapng(path: str | Path) -> Iterator[tuple[float, bytes]]:
    """Minimal pcapng reader used by tests and capture verification."""
    data = Path(path).read_bytes()
    offset = 0
    while offset + 12 <= len(data):
        block_type, total = struct.unpack_from("<II", data, offset)
        if total < 12 or offset + total > len(data):
            return
        body = data[offset + 8 : offset + total - 4]
        if block_type == PCAPNG_SHB:
            if len(body) < 4 or struct.unpack_from("<I", body, 0)[0] != BYTE_ORDER_MAGIC:
                return
        elif block_type == PCAPNG_EPB and len(body) >= 20:
            _, ts_high, ts_low, caplen, _ = struct.unpack_from("<IIIII", body, 0)
            packet = body[20 : 20 + caplen]
            if len(packet) == caplen:
                yield ((ts_high << 32) | ts_low) / 1_000_000, packet
        offset += total


def build_deauth(bssid: str, destination: str = _BROADCAST, reason: int = 7) -> bytes:
    """Build a radiotap + 802.11 deauthentication frame (monitor TX)."""
    rate = bytes([0x00, 0x02])  # flags=0, rate=1 Mbps
    radiotap = struct.pack("<BBHI", 0, 0, 8 + len(rate), (1 << 1) | (1 << 2)) + rate
    frame_control = 0x00C0  # management / deauthentication
    header = (
        struct.pack("<HH", frame_control, 0)
        + mac_to_bytes(destination)
        + mac_to_bytes(bssid)
        + mac_to_bytes(bssid)
        + struct.pack("<H", 0)
    )
    return radiotap + header + struct.pack("<H", reason)


def describe(frame: Frame) -> str:
    if frame.is_beacon or frame.is_probe_resp:
        return (
            f"AP {frame.bssid} ssid={frame.ssid or '<hidden>'} ch={frame.channel} "
            f"rssi={frame.rssi} sec={frame.privacy}"
        )
    if frame.has_eapol:
        return (
            f"EAPOL M{frame.eapol_msg} {frame.bssid} -> {frame.client}"
            + (" PMKID" if frame.pmkid else "")
        )
    if frame.is_data:
        return f"DATA {frame.bssid} {frame.src} -> {frame.dst}"
    return f"{frame.ftype}/{frame.subtype} {frame.bssid}"
