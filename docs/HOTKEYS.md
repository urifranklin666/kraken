# KRAKEN — Hotkey Guide

`Mod` is the **Super** (Windows / Command) key.
Press `Mod+F1` on the cyberdeck to open this page in a floating terminal
(`Mod+F1` → `kraken-help`; `kraken-help guide` opens the full user guide).

## Launching things

```
Mod+Return           terminal (alacritty)
Mod+Shift+Return     floating KRAKEN terminal
Mod+d                rofi application launcher
Mod+Shift+b          browser (the dashboard's chromium flags)
Mod+Shift+d          KRAKEN dashboard as an app window  (workspace 2:web)
Mod+Shift+w          KRAKEN dashboard in a browser tab
Mod+Shift+Space      KRAKEN rofi control menu
Mod+F1               this cheat sheet
Mod+Shift+e          power menu (lock / logout / restart / reboot / off)
Mod+Control+l        lock the screen
Mod+Shift+x          PANIC: stop AP, capture and interception
```

## Capture and volume

```
Print                screenshot: whole screen
Mod+Print            screenshot: drag a region
Mod+Shift+Print      screenshot: active window
XF86AudioRaiseVolume volume up          (media key)
XF86AudioLowerVolume volume down        (media key)
XF86AudioMute        volume mute        (media key)
XF86MonBrightnessUp  brightness up      (xrandr gamma fallback)
XF86MonBrightnessDown brightness down
```

Screenshots land in `~/Pictures/Screenshots/` and are copied to the clipboard.

## Windows

```
Mod+Shift+q          close the focused window
Mod+f               fullscreen
Mod+Shift+f         toggle floating
Mod+Space           toggle floating
Mod+a               focus parent container
Mod+Shift+a         focus child container
Mod+minus           show scratchpad
Mod+Shift+minus     move window to scratchpad
```

## Focus and move (vim style)

```
Mod+h / Mod+Left     focus left
Mod+j / Mod+Down     focus down
Mod+k / Mod+Up       focus up
Mod+l / Mod+Right    focus right

Mod+Shift+h / Left   move window left
Mod+Shift+j / Down   move window down
Mod+Shift+k / Up     move window up
Mod+Shift+l / Right  move window right
```

## Layout

```
Mod+b                split horizontally
Mod+v                split vertically
Mod+s                stacking layout
Mod+z                tabbed layout
Mod+e                toggle split layout
Mod+r                resize mode: h/j/k/l (or arrows), Return/Esc to leave
```

## Workspaces

```
Mod+1 … Mod+0        switch to workspace 1 … 10
Mod+Shift+1 … 0      move the focused window to workspace 1 … 10
Mod+Tab              jump to the previous workspace
Mod+Ctrl+Right       next workspace on this output
Mod+Ctrl+Left        previous workspace on this output
```

Workspace names: `1:term  2:web  3:wifi  4:cap  5:stats  6:lab  7:notes  8:media  9:sys  10:scratch`

## Session

```
Mod+Shift+c          reload i3 (keys/config)
Mod+Shift+r          restart i3 (keeps windows)
Mod+Shift+Escape     exit the i3 session (back to lightdm)
```

## Polybar (mouse)

```
workspace label      left: switch workspace
                     scroll: cycle workspaces
◈ face / counters    left: KRAKEN menu      right: dashboard
mode · chan · hops   (centre) status line, read-only
ap · cl · hs · ok    left: dashboard        right: dashboard in a tab
cpu / mem / temp     read-only system gauges
uplink iface + IP    left: KRAKEN menu
volume               right: mute            scroll: volume up/down
date / clock         left: KRAKEN menu
tray                 status icons (right edge)
```

## KRAKEN menu (rofi)

`Mod+Shift+Space` opens a menu with: live console, mode switch
(hybrid / recon / ap / idle), captive portal, handshakes, networks, clients,
logs, service restart, panic, power.

## Terminal shortcuts

```
k                    kraken CLI            ks      kraken status
kd                   dashboard (app)       kw      dashboard (tab)
km                   KRAKEN menu           ka      discovered APs
kc                   clients               kh      handshakes
kl                   daemon log tail       kdoc    kraken doctor
ksvc                 service status        klog    follow journal
welcome              fastfetch             reload-i3 / restart-i3
```

## Files that matter

```
/etc/kraken/kraken.toml      daemon + AP config (SSID, passphrase, radios)
/etc/kraken/api.token        dashboard token
/var/lib/kraken/             captures, kraken.db
/run/kraken/                 live counters the bar reads
~/.config/i3/config          this keymap
~/.config/polybar/config.ini bar layout
/usr/share/kraken/HOTKEYS.md this file
/usr/share/kraken/USER-GUIDE.md  full guide
```
