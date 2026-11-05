# KRAKEN Cyberdeck — User Guide

Raspberry Pi 4 (8 GB) booting from the 128 GB USB stick: a Tokyo Night i3
desktop around a passive WiFi recon + captive-portal AP suite.

**Authorized use only.** KRAKEN captures 802.11 management frames and can run an
isolated lab AP. Use it only on networks you own or have written permission to
test. Deauth and interception are off unless you enable them explicitly.

Related: `HOTKEYS.md` (same directory, also installed at
`/usr/share/kraken/HOTKEYS.md`, `Mod+F1`).

---

## 1. Boot and sign-in

1. Plug the USB stick into a Pi 4 and power on. The stick is the boot disk.
2. lightdm starts and logs the desktop user in automatically — no greeter, no
   password prompt.
3. i3 comes up with polybar on top, the KRAKEN wallpaper, dunst notifications,
   and (if the daemon is healthy) the dashboard on workspace `2:web`.

If you land on a console instead of the desktop, log in and run
`systemctl restart lightdm`, then check `~/.xsession-errors`.

The desktop user is the account `install.sh --user NAME` provisioned (uid 1001
by default; `echo $USER` in a terminal names it). It is in the `sudo`, `video`,
`render`, `audio` and `kraken` groups. `pi` exists but is login-disabled.

---

## 2. The desktop

Ten workspaces, named in the bar:

```
1:term  2:web  3:wifi  4:cap  5:stats  6:lab  7:notes  8:media  9:sys  10:scratch
```

The bar reads left to right:

| Segment | Meaning | Click |
|---------|---------|-------|
| workspace labels | i3 workspaces; focused is blue | left: switch, scroll: cycle |
| `◈ (-_-) zZ HYBRID 14a 3c 1h` | KRAKEN face, mode, APs, clients, handshakes | left: menu, right: dashboard |
| `hybrid · wlan1 · ch 6 · 120 hops` | mode, capture radio, channel, hop count | — |
| `14 ap · 3 cl · 1 hs · 1 ok` | discovered APs, clients, handshakes, verified captures | left/right: dashboard |
| `cpu`, `mem`, `temp` | CPU load %, RAM used %, SoC temperature °C | — |
| `eth0 192.168.1.20` | uplink interface + IPv4 (or `no uplink`) | left: menu |
| volume ramp + % | PulseAudio/PipeWire sink volume | right: mute, scroll: volume |
| `Fri 06 Nov  14:05` | date and clock | left: menu |
| tray icons | status notifiers | — |

Readings come from the daemon through `/run/kraken/*`. If the daemon is down the
face shows `offline` and the counters fall back to `—`; that is expected, not a
broken bar.

`Mod+F1` opens the cheat sheet; `Mod+Shift+Space` opens the control menu.

---

## 3. Browser

`Mod+Shift+b` starts Chromium through `kraken-browser` (dashboard URL by default,
any URL as an argument). `Mod+Shift+d` opens the dashboard as a Chromium app
window with its own class, so it lands on `2:web`.

`kraken-browser` adds the flags this hardware needs:

```
--no-first-run --no-default-browser-check --password-store=basic
--disable-features=Translate,MediaRouter --class=Chromium
```

Chromium is also the default handler for `http://`, `https://` and `text/html`
(`~/.config/mimeapps.list`), so `xdg-open` and links from notifications work.

If Chromium answers with `No usable sandbox`, the kernel has unprivileged user
namespaces off — the Pi build of Chromium has no setuid helper to fall back on.
Enable them (`sudo sysctl -w kernel.unprivileged_userns_clone=1`, persist in
`/etc/sysctl.d/`) rather than living with `--no-sandbox`.

### If Chromium refuses to start

This build crashed at login with:

```
FATAL:base/path_service.cc:264] Failed to get the path for 1001
```

`1001` is Chromium's crash-dump path. It failed because `~/.config` was owned by
root, so Chromium could not create `~/.config/chromium`. The fix, already
applied on this stick and in `install.sh`:

```sh
sudo chown -R "$USER":"$USER" ~/.config
```

Check the browser independently of the desktop:

```sh
chromium --version
kraken-browser about:blank            # graphical window
chromium --headless=new --disable-gpu --dump-dom about:blank | head
```

If a future GPU/driver update makes Chromium hang, launch it with software
rendering for one run:

```sh
KRAKEN_BROWSER_FLAGS=--disable-gpu kraken-browser about:blank
```

### Dashboard

- App window: `Mod+Shift+d` (`kraken-dashboard`)
- Browser tab: `Mod+Shift+w` (`kraken-web`)
- Manual: `http://127.0.0.1:8080/` — the token is appended automatically by
  `kraken-dashboard`; read it with `sudo cat /etc/kraken/api.token`
- HTTPS portal: `https://10.13.37.1:8443/portal` (self-signed certificate)

---

## 4. KRAKEN quick reference

```
kraken status                 daemon, radios, mode, counters
kraken mode hybrid|recon|ap|idle
kraken aps --limit 40         discovered networks
kraken clients --limit 40     observed stations
kraken handshakes             captured EAPOL/PMKID material
kraken verify <file>          check a capture with hcxtools
kraken doctor                 tools, radios, config sanity
kraken logs -n 120            daemon log
kraken ap show                AP settings and client list
kraken panic                  stop AP, capture and interception now
```

Modes:

| Mode | Radios | Use |
|------|--------|-----|
| `idle` | both released | safe parking, nothing transmitted |
| `recon` | `wlan1` monitor only | passive survey, no AP |
| `ap` | `wlan0` AP only | captive portal, no capture |
| `hybrid` | AP + monitor | default; AP on 5 GHz, recon on 2.4 GHz |

AP defaults live in `/etc/kraken/kraken.toml`: SSID `KRAKEN//LAB`,
passphrase `krakenlab`, subnet `10.13.37.1/24`, channel 36, 5 GHz.
**Change the passphrase before using this anywhere near other people**, then
`sudo systemctl restart kraken`.

Terminal aliases: `k`, `ks`, `kd`, `kw`, `km`, `ka`, `kc`, `kh`, `kl`, `kdoc`,
`ksvc`, `klog` (see `HOTKEYS.md`).

---

## 5. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Browser closes instantly / `Failed to get the path` | `~/.config` not writable by the user | `sudo chown -R "$USER":"$USER" ~/.config` |
| `No usable sandbox` from Chromium | unprivileged user namespaces disabled | `sudo sysctl -w kernel.unprivileged_userns_clone=1` |
| No transparency, shadows or rounded corners | picom exited at login | `picom --config ~/.config/picom/picom.conf --diagnostics`; the shipped config uses the `xrender` backend because the Pi's DRI2 GLX provider rejects picom's fbconfig request |
| Bar shows `%percentage%` / `%percentage:2%` | wrong token for the module version | memory uses `%percentage_used%`; the shipped config is fixed. Verify with `polybar -c ~/.config/polybar/config.ini --log=info kraken` |
| Face is missing characters (`(_) zZ`) | glyphs the bar font cannot draw | faces are now ASCII/box-drawing; the bar log shows `Dropping unmatched character` for any regression |
| Bar says `no daemon` / `offline` | `kraken.service` not running | `systemctl status kraken`, `sudo systemctl restart kraken` |
| `no uplink` | no cable/WiFi uplink, or the interface is the AP radio | `ip -br addr`, `kraken status` |
| Nothing in `kraken aps` | `wlan1` missing or not in monitor mode | `iw dev`, `kraken doctor`, reseat the RT5370 |
| No sound / volume stuck at 0 | Pi has no analog sink configured | `wpctl status`, `pactl list short sinks` |
| Dashboard says `dashboard not ready` | daemon not answering on 8080 | `systemctl status kraken`, then `kraken logs -n 80` |
| Screen stays locked / cannot unlock | no password, or i3lock failed | unlock via TTY (`Ctrl+Alt+F2`), set a password with `passwd` |
| `Mod+Shift+L` does nothing | that chord is *move window right* | lock is `Mod+Control+l` |
| i3 logs `smart_borders` / dunst logs legacy `height` | old syntax | already fixed in the shipped configs |

Logs and state:

```
~/.xsession-errors                  session, i3, picom, chromium stderr
~/.cache/polybar.log                polybar module/font warnings
journalctl -u kraken -n 100         daemon
/var/log/kraken/                    daemon log files
/var/log/Xorg.0.log                 display server and GLX
```

Restart the pieces without rebooting:

```sh
i3-msg reload                       # config changes
~/.config/polybar/launch.sh         # rebuild the bar
pkill picom; picom --config ~/.config/picom/picom.conf &
sudo systemctl restart kraken
```

---

## 6. Maintenance

The installer is idempotent and keeps existing user configs unless asked:

```sh
sudo /opt/kraken/app/install.sh              # refresh packages, scripts, configs
sudo /opt/kraken/app/install.sh --force-config   # overwrite /etc/kraken/kraken.toml
sudo /opt/kraken/app/install.sh --no-desktop     # daemon only
```

`install.sh` also copies this guide and the cheat sheet to `/usr/share/kraken/`,
the desktop home, and (when present) `/boot/firmware/`, so they stay readable
even if the graphical session is broken — mount the FAT boot partition on any
machine and open `KRAKEN-USER-GUIDE.md`.

Health check after an update:

```sh
kraken doctor
systemctl --failed
chromium --version
curl -fsS http://127.0.0.1:8080/healthz && echo ok
```

Backups: copy `/etc/kraken/` (config + token + TLS) and `/var/lib/kraken/`
(captures and `kraken.db`). The rest is reproducible from the repo.

---

## 7. Where things live

```
/opt/kraken/app/                 installed source (kraken/, install.sh, docs/)
/usr/local/bin/kraken*           CLI and desktop helpers
/etc/kraken/kraken.toml          daemon and AP configuration
/etc/kraken/api.token            dashboard token (0640 root:kraken)
/var/lib/kraken/                 captures, kraken.db, first-boot marker
/run/kraken/                     live counters consumed by polybar
/usr/share/kraken/wallpaper.png  rendered Tokyo Night backdrop
~/.config/{i3,polybar,picom,dunst,alacritty,rofi,fastfetch,cava}
~/.config/mimeapps.list          Chromium as the default browser
/usr/share/kraken/USER-GUIDE.md  this document
/usr/share/kraken/HOTKEYS.md     keymap
```
