"""Minimal CDP check: navigate the dashboard and inspect real layout metrics."""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.request

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18080/"
PORT = 9222


def wait_debugger(timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json", timeout=1) as response:
                targets = json.load(response)
            pages = [t for t in targets if t.get("type") == "page"]
            if pages:
                return pages[0]["webSocketDebuggerUrl"]
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError("debugger did not come up")


class WS:
    def __init__(self, url: str):
        _, rest = url.split("://", 1)
        hostport, path = rest.split("/", 1)
        host, port = hostport.split(":")
        self.sock = socket.create_connection((host, int(port)), timeout=15)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET /{path} HTTP/1.1\r\nHost: {hostport}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(request.encode())
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("websocket handshake failed")
            header += chunk
        if b"101" not in header.split(b"\r\n", 1)[0]:
            raise RuntimeError(header.decode(errors="replace"))
        self.buffer = header.split(b"\r\n\r\n", 1)[1]
        self.next_id = 0

    def _recv(self, count: int) -> bytes:
        while len(self.buffer) < count:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("socket closed")
            self.buffer += chunk
        data, self.buffer = self.buffer[:count], self.buffer[count:]
        return data

    def send(self, payload: dict) -> None:
        data = json.dumps(payload).encode()
        header = bytearray([0x81])
        length = len(data)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", length)
        mask = os.urandom(4)
        header += mask
        self.sock.sendall(bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def recv(self) -> dict:
        while True:
            first = self._recv(2)
            opcode = first[0] & 0x0F
            length = first[1] & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._recv(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._recv(8))[0]
            masked = first[1] & 0x80
            mask = self._recv(4) if masked else b""
            data = self._recv(length)
            if masked:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if opcode == 8:
                raise RuntimeError("websocket closed")
            if opcode == 9:
                continue
            if opcode == 1:
                return json.loads(data)

    def call(self, method: str, params: dict | None = None) -> dict:
        self.next_id += 1
        message_id = self.next_id
        self.send({"id": message_id, "method": method, "params": params or {}})
        while True:
            message = self.recv()
            if message.get("id") == message_id:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message.get("result", {})

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


EXPRESSION = r"""
(() => {
  const rect = (node) => {
    const r = node.getBoundingClientRect();
    return { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) };
  };
  const panels = [...document.querySelectorAll('.panel')].map((p) => ({ id: p.id, ...rect(p) }));
  const tiles = [...document.querySelectorAll('.tile')].map((t) => ({ id: t.querySelector('b')?.id, ...rect(t) }));
  const rowCounts = {
    aps: document.querySelectorAll('#aps-table tbody tr').length,
    clients: document.querySelectorAll('#clients-table tbody tr').length,
    captures: document.querySelectorAll('#captures-table tbody tr').length,
    events: document.querySelectorAll('#event-log .event').length,
  };
  const text = (id) => document.getElementById(id)?.textContent?.trim();
  return JSON.stringify({
    viewport: { w: innerWidth, h: innerHeight },
    document: { scrollW: document.documentElement.scrollWidth, scrollH: document.documentElement.scrollHeight },
    overflowX: document.documentElement.scrollWidth > innerWidth + 1,
    mode: document.querySelector('#mode-switch [data-active="true"]')?.dataset.mode,
    face: text('face'), mood: text('mood'), blurb: text('blurb'),
    stats: { aps: text('stat-aps'), clients: text('stat-clients'), hs: text('stat-handshakes'), frames: text('stat-frames'), size: text('stat-size') },
    kv: { mode: text('kv-mode'), monitor: text('kv-monitor'), ap: text('kv-ap'), disk: text('kv-disk') },
    rowCounts,
    chart: { ...rect(document.getElementById('chart')), bitmap: [document.getElementById('chart').width, document.getElementById('chart').height] },
    tiles,
    panels,
    apForm: { ssid: document.getElementById('ap-ssid').value, band: document.getElementById('ap-band').value, channel: document.getElementById('ap-channel').value, portal: document.getElementById('ap-portal').checked },
    activeNav: document.querySelector('.rail-nav a.active')?.textContent?.trim(),
    auth: text('auth-badge'),
    mitmDisabled: [...document.querySelectorAll('[data-toggle="mitm"]')].map((b) => b.disabled),
    aggressiveDisabled: [...document.querySelectorAll('[data-toggle="aggressive"]')].map((b) => b.disabled),
    consoleErrors: window.__errors || [],
  });
})()
"""


def main() -> int:
    profile = "/tmp/kraken-cdp-profile"
    subprocess.run(["rm", "-rf", profile], check=False)
    browser = subprocess.Popen(
        [
            "chromium", "--headless", "--no-sandbox", "--disable-gpu",
            "--disable-dev-shm-usage", f"--remote-debugging-port={PORT}",
            f"--user-data-dir={profile}", "--no-first-run", "--window-size=1600,1000",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        ws = WS(wait_debugger())
        ws.call("Page.enable")
        ws.call("Runtime.enable")
        ws.call(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": "window.__errors=[];addEventListener('error',e=>window.__errors.push(String(e.message||e.error)));addEventListener('unhandledrejection',e=>window.__errors.push('rejection:'+String(e.reason)));"},
        )
        ws.call("Page.navigate", {"url": URL})
        time.sleep(5)
        result = ws.call("Runtime.evaluate", {"expression": EXPRESSION, "returnByValue": True})
        value = result.get("result", {}).get("value")
        print(json.dumps(json.loads(value), indent=2) if value else json.dumps(result, indent=2))
        ws.close()
    finally:
        browser.terminate()
        try:
            browser.wait(timeout=5)
        except subprocess.TimeoutExpired:
            browser.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
