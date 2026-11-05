"""Command-line interface for KRAKEN."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import sys
import time
from pathlib import Path
from typing import Any

from . import APP_NAME, DEFAULT_CONFIG, __version__
from .config import Config, ConfigError
from .util import human_bytes, human_uptime, is_iface, tail_lines

RESet = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[38;5;117m"
MAGENTA = "\033[38;5;141m"
GREEN = "\033[38;5;114m"
YELLOW = "\033[38;5;179m"
RED = "\033[38;5;203m"
BLUE = "\033[38;5;111m"
GREY = "\033[38;5;243m"

BANNER = r"""
 ██╗  ██╗██████╗  █████╗ ██╗  ██╗███████╗███╗   ██╗
 ██║ ██╔╝██╔══██╗██╔══██╗██║ ██╔╝██╔════╝████╗  ██║
 █████╔╝ ██████╔╝███████║█████╔╝ █████╗  ██╔██╗ ██║
 ██╔═██╗ ██╔══██╗██╔══██║██╔═██╗ ██╔══╝  ██║╚██╗██║
 ██║  ██╗██║  ██║██║  ██║██║  ██╗███████╗██║ ╚████║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
"""


def color(text: str, code: str, *, enabled: bool = True) -> str:
    return f"{code}{text}{RESet}" if enabled else text


def _socket_path(cfg: Config) -> Path:
    return Path(cfg.general.run_dir) / "control.sock"


def request(cfg: Config, command: dict[str, Any], timeout: float = 20) -> dict[str, Any]:
    path = _socket_path(cfg)
    if not path.exists():
        raise RuntimeError(
            f"KRAKEN daemon is not running (no {path}). Start it with: sudo systemctl start kraken"
        )
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(str(path))
        sock.sendall((json.dumps(command) + "\n").encode("utf-8"))
        chunks = b""
        while b"\n" not in chunks:
            block = sock.recv(65536)
            if not block:
                break
            chunks += block
    except PermissionError as exc:
        raise RuntimeError(
            "permission denied on the KRAKEN control socket; add your user to the "
            "'kraken' group and log in again"
        ) from exc
    finally:
        sock.close()
    if not chunks:
        raise RuntimeError("daemon closed the connection without a response")
    return json.loads(chunks.split(b"\n", 1)[0].decode("utf-8"))


def _print_face(status: dict[str, Any], *, use_color: bool = True) -> None:
    face = status.get("face", {})
    print(
        color(face.get("face", "(・_・)"), MAGENTA, enabled=use_color)
        + "  "
        + color(face.get("blurb", ""), GREY, enabled=use_color)
    )


def print_status(status: dict[str, Any], *, use_color: bool = True) -> None:
    mode = str(status.get("mode", "?")).upper()
    counts = status.get("counts", {})
    capture = status.get("capture", {})
    ap = status.get("ap", {})
    uplink = status.get("uplink", {})
    face = status.get("face", {})
    print(color(BANNER, CYAN, enabled=use_color) if use_color else BANNER)
    print(
        f"  {color(APP_NAME, BOLD, enabled=use_color)} {status.get('version', '')}"
        f"  {color('//', GREY, enabled=use_color)}  {status.get('hostname', '')}"
        f"  {color('//', GREY, enabled=use_color)}  up {status.get('uptime_human', human_uptime(status.get('uptime', 0)))}"
    )
    print()
    _print_face(status, use_color=use_color)
    print()
    mode_color = {
        "HYBRID": MAGENTA,
        "RECON": CYAN,
        "AP": GREEN,
        "IDLE": GREY,
    }.get(mode, CYAN)
    print(
        f"  mode       {color(mode, mode_color, enabled=use_color):<20}"
        f" epoch {face.get('epoch', 0):<4} "
        f" channel {status.get('channel') or '-':<4} "
        f" hops {capture.get('hops', 0)}"
    )
    print(
        f"  networks   {counts.get('aps', 0):<8} clients {counts.get('clients', 0):<8} "
        f"handshakes {counts.get('handshakes', 0)} ({counts.get('verified', 0)} verified)"
    )
    print(
        f"  AP         {ap.get('ssid', '-'):<20} "
        f"{ap.get('band', '-')} GHz ch {ap.get('channel', '-')} "
        f"clients {len(ap.get('clients', []))} "
        f"{'up' if ap.get('enabled') else 'down'}"
    )
    print(
        f"  monitor    {capture.get('iface', '-'):<20} "
        f"{'capturing' if capture.get('running') else 'stopped'} "
        f"frames {capture.get('frames', 0)} "
        f"deauth {capture.get('deauths', 0)}"
    )
    print(
        f"  uplink     {str(uplink.get('iface') or 'none'):<20} "
        f"{uplink.get('ip') or '-'} "
        f"{'gw ' + str(uplink.get('gateway')) if uplink.get('gateway') else ''}"
    )
    mitm = status.get("mitm", {})
    print(
        f"  MITM       {'on' if mitm.get('enabled') else 'off':<20} "
        f"authorized={status.get('authorized', False)} "
        f"available={mitm.get('available', False)}"
    )
    print(
        f"  capture    {capture.get('capture') or '-'} "
        f"({human_bytes(capture.get('capture_size', 0))})"
    )
    if status.get("warnings"):
        print()
        for warning in status["warnings"]:
            print("  " + color(f"! {warning}", YELLOW, enabled=use_color))
    print(
        "  "
        + color(
            f"dashboard http://127.0.0.1:{status.get('config', {}).get('general', {}).get('http_port', 8080)}/",
            BLUE,
            enabled=use_color,
        )
    )


def cmd_status(cfg: Config, args: argparse.Namespace) -> int:
    response = request(cfg, {"cmd": "status"})
    if not response.get("ok"):
        print(response.get("error", "unknown error"), file=sys.stderr)
        return 1
    status = response["status"]
    if args.json:
        print(json.dumps(status, indent=2, default=str))
    else:
        print_status(status)
    return 0


def cmd_mode(cfg: Config, args: argparse.Namespace) -> int:
    response = request(cfg, {"cmd": "mode", "value": args.mode})
    if not response.get("ok"):
        print(color("failed: ", RED) + str(response.get("error")), file=sys.stderr)
        if response.get("errors"):
            for error in response["errors"]:
                print("  " + error, file=sys.stderr)
        return 1
    print(f"mode -> {response.get('mode')}")
    if response.get("errors"):
        for error in response["errors"]:
            print("  " + color(error, YELLOW))
    return 0


def cmd_ap(cfg: Config, args: argparse.Namespace) -> int:
    if args.ap_action == "show":
        response = request(cfg, {"cmd": "status"})
        if not response.get("ok"):
            print(response.get("error"), file=sys.stderr)
            return 1
        print(json.dumps(response["status"]["ap"], indent=2, default=str))
        return 0
    payload: dict[str, Any] = {"cmd": "ap"}
    if args.ssid is not None:
        payload["ssid"] = args.ssid
    if args.passphrase is not None:
        payload["passphrase"] = args.passphrase
    if args.channel is not None:
        payload["channel"] = args.channel
    if args.band is not None:
        payload["band"] = args.band
    if args.portal is not None:
        payload["portal"] = args.portal
    response = request(cfg, payload, timeout=90)
    if not response.get("ok"):
        print(response.get("error", "unknown error"), file=sys.stderr)
        return 1
    ap = response.get("ap", {})
    print(
        f"AP updated: {ap.get('ssid')} {ap.get('band')} GHz ch {ap.get('channel')} "
        f"portal={'on' if ap.get('portal') else 'off'}"
    )
    return 0


def cmd_toggle(cfg: Config, args: argparse.Namespace) -> int:
    response = request(cfg, {"cmd": args.toggle, "enabled": args.value == "on"})
    if not response.get("ok"):
        print(response.get("error", "unknown error"), file=sys.stderr)
        return 1
    print(f"{args.toggle} -> {args.value}")
    return 0


def cmd_handshakes(cfg: Config, args: argparse.Namespace) -> int:
    response = request(cfg, {"cmd": "handshakes", "limit": args.limit})
    if not response.get("ok"):
        print(response.get("error"), file=sys.stderr)
        return 1
    rows = response.get("handshakes", [])
    if not rows:
        print("No handshakes captured yet.")
        return 0
    print(f"{'ID':>4}  {'WHEN':<17}  {'KIND':<6}  {'BSSID':<17}  {'SSID':<22}  {'SIZE':>8}  VER")
    for row in rows:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["ts"]))
        print(
            f"{row['id']:>4}  {when:<17}  {row['kind']:<6}  {row['bssid']:<17}  "
            f"{(row['ssid'] or '<hidden>')[:22]:<22}  {human_bytes(row['size']):>8}  "
            f"{'yes' if row['verified'] else 'raw'}"
        )
    return 0


def cmd_aps(cfg: Config, args: argparse.Namespace) -> int:
    response = request(cfg, {"cmd": "aps", "limit": args.limit})
    if not response.get("ok"):
        print(response.get("error"), file=sys.stderr)
        return 1
    rows = response.get("aps", [])
    print(f"{'SSID':<24}  {'BSSID':<17}  CH  RSSI  SEC      LAST")
    for row in rows:
        last = time.strftime("%H:%M:%S", time.localtime(row["last_seen"]))
        print(
            f"{(row['ssid'] or '<hidden>')[:24]:<24}  {row['bssid']:<17}  "
            f"{str(row['channel'] or '-'):<2}  {str(row['rssi'] or '-'):>4}  "
            f"{(row['privacy'] or '?'):<8} {last}"
        )
    return 0


def cmd_clients(cfg: Config, args: argparse.Namespace) -> int:
    response = request(cfg, {"cmd": "clients", "limit": args.limit})
    if not response.get("ok"):
        print(response.get("error"), file=sys.stderr)
        return 1
    rows = response.get("clients", [])
    print(f"{'CLIENT':<17}  {'BSSID':<17}  RSSI  LAST")
    for row in rows:
        last = time.strftime("%H:%M:%S", time.localtime(row["last_seen"]))
        print(
            f"{row['mac']:<17}  {(row['bssid'] or '-'):<17}  "
            f"{str(row['rssi'] or '-'):>4}  {last}"
        )
    return 0


def cmd_verify(cfg: Config, args: argparse.Namespace) -> int:
    response = request(cfg, {"cmd": "verify", "id": args.id}, timeout=300)
    if not response.get("ok"):
        print(response.get("error"), file=sys.stderr)
        return 1
    print(("verified: " if response.get("verified") else "no hashes: ") + response.get("note", ""))
    return 0 if response.get("verified") else 2


def cmd_download(cfg: Config, args: argparse.Namespace) -> int:
    response = request(cfg, {"cmd": "handshakes", "limit": 1000})
    if not response.get("ok"):
        print(response.get("error"), file=sys.stderr)
        return 1
    handshake = next(
        (row for row in response.get("handshakes", []) if row["id"] == args.id), None
    )
    if not handshake:
        print(f"handshake #{args.id} not found", file=sys.stderr)
        return 1
    source = Path(handshake["path"])
    target = Path(args.out or Path.cwd() / source.name)
    try:
        shutil.copyfile(source, target)
    except OSError as exc:
        print(f"cannot copy {source}: {exc}", file=sys.stderr)
        return 1
    print(f"copied {source} -> {target}")
    return 0


def cmd_logs(cfg: Config, args: argparse.Namespace) -> int:
    response = request(cfg, {"cmd": "logs", "lines": args.lines})
    if not response.get("ok"):
        print(response.get("error"), file=sys.stderr)
        return 1
    for line in response.get("logs", []):
        print(line)
    return 0


def cmd_face(cfg: Config, args: argparse.Namespace) -> int:
    response = request(cfg, {"cmd": "status"})
    if not response.get("ok"):
        print(response.get("error"), file=sys.stderr)
        return 1
    status = response["status"]
    print(status["face"].get("face", ""))
    print(status["face"].get("blurb", ""))
    print(
        f"mood={status['face'].get('mood')} epoch={status['face'].get('epoch')} "
        f"mode={status.get('mode')}"
    )
    return 0


def cmd_web(cfg: Config, args: argparse.Namespace) -> int:
    url = f"http://127.0.0.1:{cfg.general.http_port}/"
    if args.print_only:
        print(url)
        return 0
    for opener in ("kraken-browser", "xdg-open", "chromium", "firefox"):
        if shutil.which(opener):
            os.execvp(opener, [opener, url])
    print(url)
    return 0


def cmd_menu(cfg: Config, args: argparse.Namespace) -> int:
    if shutil.which("kraken-menu"):
        os.execvp("kraken-menu", ["kraken-menu"])
    print("kraken-menu is not installed", file=sys.stderr)
    return 1


def cmd_doctor(cfg: Config, args: argparse.Namespace) -> int:
    failures = 0
    print(color(f"{APP_NAME} doctor", BOLD))
    print(f"config      {cfg.source}")
    try:
        cfg.validate()
        print(color("  ok", GREEN) + " configuration valid")
    except ConfigError as exc:
        failures += 1
        print(color("  fail", RED) + f" {exc}")

    tools = ["iw", "ip", "hostapd", "dnsmasq", "nft", "hcxpcapngtool", "openssl"]
    for tool in tools:
        path = shutil.which(tool)
        if path:
            print(color("  ok", GREEN) + f" {tool:<14} {path}")
        else:
            failures += 1
            print(color("  fail", RED) + f" {tool:<14} missing")

    for iface in (cfg.radio.monitor_iface, cfg.radio.ap_iface):
        exists = Path(f"/sys/class/net/{iface}").exists()
        wireless = Path(f"/sys/class/net/{iface}/wireless").exists()
        if exists and wireless:
            print(color("  ok", GREEN) + f" {iface:<14} wireless")
        else:
            failures += 1
            print(color("  fail", RED) + f" {iface:<14} missing or not wireless")

    if shutil.which("nmcli"):
        print(color("  ok", GREEN) + " NetworkManager present")
    else:
        print(color("  warn", YELLOW) + " nmcli missing; radios may need manual management")

    if not shutil.which("bettercap"):
        print(color("  warn", YELLOW) + " bettercap missing; MITM unavailable (optional)")

    try:
        response = request(cfg, {"cmd": "ping"}, timeout=3)
        print(color("  ok", GREEN) + f" daemon reachable ({response.get('version')})")
    except Exception:
        print(color("  warn", YELLOW) + " daemon not running")

    return 0 if failures == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kraken",
        description="KRAKEN WiFi cyberdeck: pwnagotchi-style recon + captive-portal AP.",
    )
    parser.add_argument("--config", default=os.environ.get("KRAKEN_CONFIG", DEFAULT_CONFIG))
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="show daemon status")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    mode = sub.add_parser("mode", help="switch operating mode")
    mode.add_argument("mode", choices=["hybrid", "recon", "ap", "idle"])
    mode.set_defaults(func=cmd_mode)

    ap = sub.add_parser("ap", help="show or configure the access point")
    ap.add_argument("ap_action", nargs="?", default="set", choices=["set", "show"])
    ap.add_argument("--ssid")
    ap.add_argument("--passphrase", "--pass")
    ap.add_argument("--channel", type=int)
    ap.add_argument("--band", choices=["5", "2.4"])
    portal = ap.add_mutually_exclusive_group()
    portal.add_argument("--portal", dest="portal", action="store_true")
    portal.add_argument("--no-portal", dest="portal", action="store_false")
    ap.set_defaults(portal=None, func=cmd_ap)

    for name, help_text in (
        ("mitm", "toggle ARP/HTTP interception (requires --authorized daemon)"),
        ("aggressive", "toggle deauthentication (authorized networks only)"),
    ):
        toggle = sub.add_parser(name, help=help_text)
        toggle.add_argument("value", choices=["on", "off"])
        toggle.set_defaults(func=cmd_toggle, toggle=name)

    handshakes = sub.add_parser("handshakes", help="list captured EAPOL/PMKID material")
    handshakes.add_argument("--limit", type=int, default=50)
    handshakes.set_defaults(func=cmd_handshakes)

    aps = sub.add_parser("aps", help="list discovered access points")
    aps.add_argument("--limit", type=int, default=100)
    aps.set_defaults(func=cmd_aps)

    clients = sub.add_parser("clients", help="list observed clients")
    clients.add_argument("--limit", type=int, default=100)
    clients.set_defaults(func=cmd_clients)

    verify = sub.add_parser("verify", help="verify a capture with hcxtools")
    verify.add_argument("id", type=int)
    verify.set_defaults(func=cmd_verify)

    download = sub.add_parser("download", help="copy a capture file")
    download.add_argument("id", type=int)
    download.add_argument("--out")
    download.set_defaults(func=cmd_download)

    logs = sub.add_parser("logs", help="tail the daemon log")
    logs.add_argument("-n", "--lines", type=int, default=100)
    logs.set_defaults(func=cmd_logs)

    face = sub.add_parser("face", help="print the current face")
    face.set_defaults(func=cmd_face)

    web = sub.add_parser("web", help="open the dashboard")
    web.add_argument("--print-only", action="store_true")
    web.set_defaults(func=cmd_web)

    menu = sub.add_parser("menu", help="open the rofi control menu")
    menu.set_defaults(func=cmd_menu)

    doctor = sub.add_parser("doctor", help="check tools, radios and configuration")
    doctor.set_defaults(func=cmd_doctor)

    daemon = sub.add_parser("daemon", help="run in the foreground (root)")
    daemon.add_argument(
        "--authorized",
        action="store_true",
        help="enable opt-in MITM/deauth capabilities for authorized testing",
    )
    daemon.set_defaults(func=None)

    panic = sub.add_parser("panic", help="stop AP, recon and MITM immediately")
    panic.set_defaults(func=lambda cfg, args: _panic(cfg))

    return parser


def _panic(cfg: Config) -> int:
    response = request(cfg, {"cmd": "panic"}, timeout=60)
    print("stopped" if response.get("ok") else response.get("error"))
    return 0 if response.get("ok") else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cfg = Config.load(args.config)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    if args.command == "daemon":
        if os.geteuid() != 0:
            print("the daemon must run as root (needs raw sockets, hostapd and nftables)", file=sys.stderr)
            return 1
        from .daemon import run_daemon

        return run_daemon(cfg, authorized=bool(args.authorized))

    try:
        return int(args.func(cfg, args))
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
