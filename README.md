# KRAKEN

A Raspberry Pi 4 WiFi cyberdeck: pwnagotchi-style passive recon and handshake
capture on one radio, a Pineapple-style access point with a captive portal on
the other, an operator dashboard, and a Tokyo Night i3 desktop.

**Authorized use only.** This software captures 802.11 management frames and can
run an isolated lab AP. Use it only on networks you own or have written
permission to test. Deauthentication and interception are disabled by default
and require explicit `--authorized` flags; there is no credential harvesting,
TLS stripping, or payload delivery.

## Documentation

| Document | Contents |
|----------|----------|
| `docs/USER-GUIDE.md` | boot, desktop tour, bar reference, browser, troubleshooting |
| `docs/HOTKEYS.md` | every i3 binding, polybar click and terminal alias |

`install.sh` copies both to `/usr/share/kraken/`, the desktop user's home, and
`/boot/firmware/`; on the cyberdeck `Mod+F1` shows the cheat sheet.

## Hardware

| Interface | Radio | Role |
|-----------|-------|------|
| `wlan0` | onboard BCM43455 | 5 GHz AP + captive portal (no monitor mode) |
| `wlan1` | USB Ralink RT5370 | 2.4 GHz monitor, recon, handshake capture, injection |
| `eth0` | 1 GbE | uplink / NAT (optional) |

A single radio cannot be an AP and a monitor at the same time. KRAKEN therefore
runs in **hybrid** mode: `wlan0` serves the AP while `wlan1` hops 2.4 GHz
channels. If `wlan1` is missing the daemon still serves the AP and reports the
reduced capability in `kraken doctor`.

## Architecture

```
 wlan1 (monitor) ──► capture.py ──► pcapng + hcxtools ──► SQLite (WAL)
                                      │
 wlan0 (AP) ─────► ap.py (hostapd + dnsmasq + nftables NAT)
                                      │
                        daemon.py ────┴──► Unix socket IPC ──► kraken CLI
                                      └──► HTTP/SSE dashboard (token)
                                      └──► /run/kraken/* (polybar)
```

* Python 3 standard library only; no pip dependencies.
* `systemd` unit `kraken.service`, plus a one-shot `kraken-firstboot.service`.
* Web UI at port 8080 (HTTP) and 8443 (HTTPS, self-signed).
* Captures live in `/var/lib/kraken/captures`; state in `kraken.db`.
* The daemon is the only component that needs root.

## Provision the 128 GB USB

From the running Pi (this erases the target disk):

```sh
sudo ./provision-usb.sh --device /dev/sda
```

The script downloads Raspberry Pi OS Lite (arm64, trixie), verifies its SHA-256,
streams it to the USB, expands the root partition, creates the desktop user with
your current password hash and SSH keys, and runs `install.sh` inside a chroot.
It refuses the disk that hosts `/` and asks you to type the device name.

Useful flags:

```sh
--dry-run                 # checks and plan only
--image-file out.img --size 16G --compress   # build a flashable .img.xz instead
--no-mitm                 # skip bettercap
--eeprom-usb-first        # Pi 4 EEPROM boot order: USB before SD
--cache DIR               # where to keep the downloaded image
```

After provisioning: power off, remove the SD card (or set USB-first boot),
insert the USB, and power on. The desktop autologins to i3.

## Live install (already-running Raspberry Pi OS)

```sh
sudo ./install.sh
```

`install.sh` is idempotent. Existing configs are preserved; use
`--force-config` to replace `/etc/kraken/kraken.toml`. It does **not** start the
daemon automatically, because taking over `wlan0` would drop an SSH session.
Reboot or run `sudo systemctl start kraken` when ready.

Options: `--user NAME`, `--home PATH`, `--hostname NAME`, `--no-desktop`,
`--no-mitm`, `--skip-packages`, `--no-clean`.

## First login

* Desktop user: the account you provisioned (autologin).
* Dashboard: `http://kraken.local:8080/` or `http://10.13.37.1:8080/`.
* Token: `sudo cat /etc/kraken/api.token` (also accepted in the dashboard dialog).
* Config: `/etc/kraken/kraken.toml` (mode `0640`, group `kraken`).
* Service: `systemctl status kraken`, `journalctl -u kraken -f`.

Change the default SSID and passphrase in the `[ap]` section before using this
near other people. The shipped passphrase is `krakenlab`.

## CLI

```
kraken status                 mode, face, counters, radios
kraken mode hybrid|recon|ap|off
kraken ap on|off [--ssid S] [--passphrase P] [--band 5|2.4] [--channel N]
kraken mitm on|off --authorized
kraken aggressive on|off --authorized
kraken handshakes [--limit N]
kraken aps [--limit N]
kraken clients
kraken verify ID
kraken download ID --output FILE
kraken logs [-n N]
kraken face
kraken web [--port N]
kraken menu                   rofi control panel
kraken doctor                 dependency and radio diagnostics
kraken panic                  stop AP/capture immediately
kraken daemon [--authorized]  foreground daemon (systemd runs this)
```

The CLI speaks JSON lines over `/run/kraken/control.sock`; group `kraken` can
use it without sudo. Only `systemctl restart kraken` is allowed via sudoers.

## Desktop

Tokyo Night neon theme throughout:

* **i3** with gaps (`Mod+Return` terminal, `Mod+d` rofi, `Mod+Shift+d`
  dashboard, `Mod+Shift+space` KRAKEN menu, `Mod+Shift+x` panic).
* **polybar** with face/mood, mode, AP/client/handshake counters, channel,
  uplink, CPU/memory/temp/audio/clock.
* **picom**, **dunst**, **alacritty**, **cava**, **fastfetch**, **feh**
  wallpaper, **rofi** launcher, **i3lock**.
* **LightDM** autologin to the `kraken-i3` session.
* Helper scripts: `kraken-menu`, `kraken-power`, `kraken-screenshot`,
  `kraken-volume`, `kraken-brightness`, `kraken-lock`, `kraken-dashboard`.

Existing desktop configs are backed up as `*.pre-kraken` on first install.

## Configuration

`config/kraken.toml` is the annotated sample. Main sections:

* `[general]` — hostname, data/run/log dirs, HTTP/HTTPS ports, `open_read`
  (false: every read needs the token), token/cert paths.
* `[radio]` — monitor interface, AP interface, regulatory domain, channel hop
  list and dwell time.
* `[recon]` — passive capture, minimum RSSI, PMKID/EAPOL options, whitelist and
  blacklist, `aggressive` (requires authorization at runtime).
* `[ap]` — SSID, passphrase, band/channel, portal, client isolation, uplink.
* `[mitm]` — `allow` (package present), `auto` (start with the daemon; default
  false). Turning it on requires `--authorized` and an explicit `kraken mitm on`.

## Security posture

* Passive capture by default; no deauth unless a BSSID is on the whitelist **and**
  the daemon was started with `--authorized`.
* MITM and aggressive channel hopping require `--authorized`; the daemon forces
  `aggressive=false` at startup otherwise.
* Dashboard reads require the API token by default; the captive portal has a
  separate public `/api/portal` endpoint with no secrets.
* TLS key and token are `0640 root:kraken`; the config is `0640 root:kraken`.
* The AP is isolated (`ap_isolate=1`) and NATs only the configured uplink.
* The portal collects no credentials, email addresses, or payment data.

## Troubleshooting

```sh
kraken doctor
iw dev
rfkill list
nmcli device status
ip -br addr
nft list ruleset
journalctl -u kraken -n 100 --no-pager
```

* `wlan1` busy when starting monitor mode: `sudo nmcli device set wlan1 managed no`
  (the daemon does this, then restores it on stop).
* AP clients get no address: check `dnsmasq` is running under the daemon, not the
  distro unit (the distro units are masked).
* No `wlan1`: the RT5370 needs `rt2870.bin` (from `firmware-misc-nonfree`, and
  copied by hand when the USB is provisioned); check `dmesg | grep rt2`.
* Dashboard asks for a token: read `/etc/kraken/api.token`; the token is stored
  per browser tab in `sessionStorage`.
* Desktop does not start: `systemctl status lightdm`, `ls /usr/share/xsessions`,
  and check `~/.config/i3/config` with `i3 -C -c ~/.config/i3/config`.

## Rebuilding / duplicating

Build a compressed image on a host with at least 6 GB free:

```sh
sudo ./provision-usb.sh --image-file build/kraken-16g.img --size 16G --compress
```

Write it with Raspberry Pi Imager, balenaEtcher, or:

```sh
xz -dc build/kraken-16g.img.xz | sudo dd of=/dev/sdX bs=4M conv=fsync status=progress
```

## Layout

```
kraken/            Python package (daemon, capture, AP, web, CLI, face)
kraken/assets/     dashboard, portal, CSS, JS
config/            annotated kraken.toml
desktop/           i3, polybar, rofi, picom, alacritty, dunst, cava, fastfetch
scripts/           helper and polybar scripts (installed to /usr/local/bin)
systemd/           kraken.service, kraken-firstboot.service
tests/             unittest suite (python3 -m unittest discover -s tests)
tools/             dashboard preview and CDP layout checks (dev only)
install.sh         live/chroot installer
provision-usb.sh   USB/image builder
```
