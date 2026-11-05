#!/usr/bin/env bash
# KRAKEN installer — live Raspberry Pi OS or chroot into a mounted image.
#
#   sudo ./install.sh                       # install on this running system
#   sudo ./install.sh --image --user pi     # inside a mounted image chroot
#
# The installer is idempotent: existing configs are preserved unless --force-config.
set -euo pipefail
umask 027

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_MODE=0
KUSER=""
KHOME=""
KHOST="kraken"
WITH_MITM=1
WITH_DESKTOP=1
FORCE_CONFIG=0
SKIP_PACKAGES=0
CLEAN=1

log()  { printf '\033[38;5;117m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[38;5;179m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[38;5;203m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
usage: install.sh [options]

  --image              installing inside a mounted image/chroot
  --user NAME          desktop user (default: $SUDO_USER or uid 1000)
  --home PATH          home directory (default: from passwd)
  --hostname NAME      hostname to set (default: kraken)
  --with-mitm          install bettercap for opt-in interception (default)
  --no-mitm            skip bettercap
  --no-desktop         skip i3/polybar/lightdm and only install the daemon
  --force-config       overwrite /etc/kraken/kraken.toml
  --skip-packages      do not run apt
  --no-clean           keep apt lists and caches
  -h, --help
EOF
}

while (($#)); do
    case "$1" in
        --image) IMAGE_MODE=1 ;;
        --user) KUSER="${2:?--user needs a name}"; shift ;;
        --home) KHOME="${2:?--home needs a path}"; shift ;;
        --hostname) KHOST="${2:?--hostname needs a name}"; shift ;;
        --with-mitm) WITH_MITM=1 ;;
        --no-mitm) WITH_MITM=0 ;;
        --no-desktop) WITH_DESKTOP=0 ;;
        --force-config) FORCE_CONFIG=1 ;;
        --skip-packages) SKIP_PACKAGES=1 ;;
        --no-clean) CLEAN=0 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done

[[ "$(id -u)" -eq 0 ]] || die "run as root (sudo ./install.sh)"

if [[ -z "$KUSER" ]]; then
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        KUSER="$SUDO_USER"
    else
        KUSER="$(getent passwd 1000 | cut -d: -f1 || true)"
    fi
fi
[[ -n "$KUSER" && "$KUSER" != "root" ]] || die "cannot determine the desktop user; pass --user NAME"
[[ "$KUSER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "invalid user name: $KUSER"
[[ "$KHOST" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] || die "invalid hostname: $KHOST"
getent passwd "$KUSER" >/dev/null || die "user '$KUSER' does not exist"
[[ -n "$KHOME" ]] || KHOME="$(getent passwd "$KUSER" | cut -d: -f6)"
[[ -n "$KHOME" ]] || die "cannot determine home for '$KUSER'"
KGROUP="$(id -gn "$KUSER")"

LIVE=0
[[ -d /run/systemd/system ]] && LIVE=1

log "KRAKEN installer"
log "mode: $([[ $IMAGE_MODE -eq 1 ]] && echo image/chroot || echo live)  user: $KUSER  home: $KHOME  host: $KHOST"

# ---------------------------------------------------------------- packages
PKGS=(
    python3
    iw wireless-regdb rfkill iproute2
    hostapd dnsmasq nftables
    hcxtools hcxdumptool aircrack-ng
    openssl curl ca-certificates
    network-manager
    avahi-daemon libnss-mdns
    openssh-server openssh-client sudo usbutils
    firmware-misc-nonfree
    tcpdump nmap
    fonts-jetbrains-mono fonts-font-awesome
    unzip git
)
DESKTOP_PKGS=(
    xserver-xorg xinit x11-xserver-utils
    i3-wm polybar rofi picom feh dunst alacritty
    chromium
    lightdm lightdm-gtk-greeter
    maim xclip xdotool wmctrl i3lock
    brightnessctl pamixer pulseaudio-utils
    pipewire pipewire-pulse wireplumber
    cava fastfetch
    librsvg2-bin
    papirus-icon-theme
)

apt_install() {
    local requested=("$@")
    local packages=()
    local pkg
    ((${#requested[@]})) || return 0
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || warn "apt-get update failed; continuing with the existing cache"
    for pkg in "${requested[@]}"; do
        if apt-cache show "$pkg" >/dev/null 2>&1; then
            packages+=("$pkg")
        else
            warn "package not in the archive, skipping: $pkg"
        fi
    done
    if ((${#packages[@]} == 0)); then
        warn "apt cache is empty; trying the requested set directly"
        packages=("${requested[@]}")
    fi
    ((${#packages[@]})) || return 0
    log "installing ${#packages[@]} packages"
    if ! apt-get install -y --no-install-recommends "${packages[@]}"; then
        warn "batch install failed; retrying packages individually"
        for pkg in "${packages[@]}"; do
            apt-get install -y --no-install-recommends "$pkg" || warn "package failed to install: $pkg"
        done
    fi
}

if [[ $SKIP_PACKAGES -eq 0 ]]; then
    command -v apt-get >/dev/null || die "apt-get not found"
    apt_install "${PKGS[@]}"
    if [[ $WITH_DESKTOP -eq 1 ]]; then
        if ! apt_install "${DESKTOP_PKGS[@]}"; then
            warn "desktop package set failed"
        fi
        if ! command -v chromium >/dev/null 2>&1 && ! command -v chromium-browser >/dev/null 2>&1; then
            apt_install chromium-browser || warn "no chromium package available"
        fi
    fi
    if [[ $WITH_MITM -eq 1 ]]; then
        apt_install bettercap || warn "bettercap unavailable; MITM will stay disabled"
    fi
else
    log "skipping package installation"
fi

# ------------------------------------------------------------- users/groups
getent group kraken >/dev/null || groupadd --system kraken
getent group autologin >/dev/null || groupadd --system autologin
usermod -aG kraken "$KUSER"
if [[ $WITH_DESKTOP -eq 1 ]]; then
    usermod -aG autologin "$KUSER"
fi

# ------------------------------------------------------------------- layout
install -d -m 0755 /opt/kraken /opt/kraken/app
install -d -m 0750 /etc/kraken /etc/kraken/tls
install -d -m 0750 /var/lib/kraken /var/log/kraken
install -d -m 0770 /run/kraken
install -d -m 0755 /usr/share/kraken

log "copying application to /opt/kraken/app"
tar -C "$ROOT" \
    --exclude=.git --exclude=image --exclude=tools \
    --exclude='__pycache__' --exclude='*.pyc' \
    -cf - . | tar -C /opt/kraken/app -xf -
find /opt/kraken/app -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true

cat >/usr/local/bin/kraken <<'PY'
#!/usr/bin/python3
import sys

sys.path.insert(0, "/opt/kraken/app")
from kraken.__main__ import main

raise SystemExit(main())
PY
chmod 0755 /usr/local/bin/kraken

log "installing helper scripts"
install -d -m 0755 /usr/local/bin
for script in "$ROOT"/scripts/*; do
    [[ -f "$script" ]] || continue
    install -m 0755 "$script" "/usr/local/bin/$(basename "$script")"
done

# -------------------------------------------------------------------- config
if [[ ! -f /etc/kraken/kraken.toml || $FORCE_CONFIG -eq 1 ]]; then
    log "writing /etc/kraken/kraken.toml"
    sed "s/^hostname = .*/hostname = \"$KHOST\"/" "$ROOT/config/kraken.toml" >/etc/kraken/kraken.toml
else
    log "keeping existing /etc/kraken/kraken.toml"
fi
chown root:kraken /etc/kraken/kraken.toml
chmod 0640 /etc/kraken/kraken.toml

if [[ ! -s /etc/kraken/api.token ]]; then
    log "generating API token"
    openssl rand -hex 24 >/etc/kraken/api.token
fi
chown root:kraken /etc/kraken/api.token
chmod 0640 /etc/kraken/api.token

if [[ ! -s /etc/kraken/tls/cert.pem || ! -s /etc/kraken/tls/key.pem ]]; then
    log "generating self-signed TLS certificate"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /etc/kraken/tls/key.pem -out /etc/kraken/tls/cert.pem \
        -days 825 -subj "/CN=${KHOST}.local" \
        -addext "subjectAltName=DNS:${KHOST}.local,IP:10.13.37.1,IP:127.0.0.1" >/dev/null 2>&1
fi
chown root:kraken /etc/kraken/tls/key.pem
chmod 0640 /etc/kraken/tls/key.pem
chmod 0644 /etc/kraken/tls/cert.pem
chmod 0750 /etc/kraken/tls

# ------------------------------------------------------------------- sysctl
cat >/etc/sysctl.d/90-kraken.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF
if [[ $LIVE -eq 1 ]]; then
    sysctl --system >/dev/null 2>&1 || warn "sysctl could not be applied now"
fi

# ------------------------------------------------------------------ services
if [[ $IMAGE_MODE -eq 1 ]]; then
    log "writing hostname (image mode)"
    printf '%s\n' "$KHOST" >/etc/hostname
    if grep -q '^127\.0\.1\.1' /etc/hosts; then
        sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$KHOST/" /etc/hosts
    else
        printf '127.0.1.1\t%s\n' "$KHOST" >>/etc/hosts
    fi
elif [[ $LIVE -eq 1 ]]; then
    hostnamectl set-hostname "$KHOST" 2>/dev/null || warn "hostnamectl failed"
fi

install -m 0644 "$ROOT/systemd/kraken.service" /etc/systemd/system/kraken.service
install -m 0644 "$ROOT/systemd/kraken-firstboot.service" /etc/systemd/system/kraken-firstboot.service

systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable kraken.service >/dev/null 2>&1 || warn "could not enable kraken.service"
systemctl enable kraken-firstboot.service >/dev/null 2>&1 || warn "could not enable kraken-firstboot.service"
systemctl disable hostapd.service dnsmasq.service >/dev/null 2>&1 || true
if [[ $LIVE -eq 1 ]]; then
    systemctl stop hostapd.service dnsmasq.service >/dev/null 2>&1 || true
fi
systemctl mask hostapd.service dnsmasq.service >/dev/null 2>&1 || true
systemctl disable bettercap.service >/dev/null 2>&1 || true
systemctl mask bettercap.service >/dev/null 2>&1 || true
systemctl enable avahi-daemon.service >/dev/null 2>&1 || true

# The Pi OS first-boot user wizard must not race our pre-created account.
if [[ -f /lib/systemd/system/userconfig.service || -f /usr/lib/systemd/system/userconfig.service ]]; then
    systemctl disable userconfig.service >/dev/null 2>&1 || true
    systemctl mask userconfig.service >/dev/null 2>&1 || true
fi

# -------------------------------------------------------------- sudo access
SUDO_BIN="$(command -v systemctl || echo /usr/bin/systemctl)"
cat >/tmp/010-kraken.sudoers <<EOF
Cmnd_Alias KRAKEN_SERVICE = $SUDO_BIN restart kraken, $SUDO_BIN start kraken, $SUDO_BIN stop kraken, $SUDO_BIN status kraken, $SUDO_BIN is-active kraken
%kraken ALL=(root) NOPASSWD: KRAKEN_SERVICE
$KUSER ALL=(root) NOPASSWD: KRAKEN_SERVICE
EOF
if visudo -cf /tmp/010-kraken.sudoers >/dev/null 2>&1; then
    install -m 0440 -o root -g root /tmp/010-kraken.sudoers /etc/sudoers.d/010-kraken
else
    warn "sudoers validation failed; service restart from the menu will ask for a password"
fi
rm -f /tmp/010-kraken.sudoers

# ------------------------------------------------------------------- desktop
install_user_file() {
    local src="$1" dst="$2" mode="${3:-0644}"
    install -d -o "$KUSER" -g "$KGROUP" -m 0755 "$(dirname "$dst")"
    if [[ -f "$dst" ]] && ! cmp -s "$src" "$dst" && [[ ! -e "$dst.pre-kraken" ]]; then
        cp -a "$dst" "$dst.pre-kraken"
    fi
    install -m "$mode" -o "$KUSER" -g "$KGROUP" "$src" "$dst"
}

if [[ $WITH_DESKTOP -eq 1 ]]; then
    log "installing the Tokyo Night desktop"
    UCONF="$KHOME/.config"

    install_user_file "$ROOT/desktop/i3/config" "$UCONF/i3/config"
    install_user_file "$ROOT/desktop/polybar/config.ini" "$UCONF/polybar/config.ini"
    install_user_file "$ROOT/desktop/polybar/launch.sh" "$UCONF/polybar/launch.sh" 0755
    install_user_file "$ROOT/desktop/rofi/kraken.rasi" "$UCONF/rofi/kraken.rasi"
    install_user_file "$ROOT/desktop/picom/picom.conf" "$UCONF/picom/picom.conf"
    install_user_file "$ROOT/desktop/alacritty/alacritty.toml" "$UCONF/alacritty/alacritty.toml"
    install_user_file "$ROOT/desktop/dunst/dunstrc" "$UCONF/dunst/dunstrc"
    install_user_file "$ROOT/desktop/fastfetch/config.jsonc" "$UCONF/fastfetch/config.jsonc"
    install_user_file "$ROOT/desktop/fastfetch/kraken.txt" "$UCONF/fastfetch/kraken.txt"
    install_user_file "$ROOT/desktop/cava/config" "$UCONF/cava/config"
    install_user_file "$ROOT/desktop/chromium/mimeapps.list" "$UCONF/mimeapps.list"

    # ~/.config must belong to the user: chromium, dconf and friends create
    # their state here and abort at startup if it is root-owned.
    install -d -o "$KUSER" -g "$KGROUP" -m 0755 "$UCONF"
    chown -R "$KUSER:$KGROUP" "$UCONF"

    install -d -m 0755 "$KHOME/Pictures/Screenshots"
    chown "$KUSER:$KGROUP" "$KHOME/Pictures" "$KHOME/Pictures/Screenshots" 2>/dev/null || true

    install -m 0644 "$ROOT/desktop/shell/bashrc" /etc/profile.d/kraken.sh
    if ! grep -q 'KRAKEN_SHELL_SNIPPET' "$KHOME/.bashrc" 2>/dev/null; then
        cat >>"$KHOME/.bashrc" <<'EOF'

# KRAKEN_SHELL_SNIPPET
if [ -r /etc/profile.d/kraken.sh ]; then
    . /etc/profile.d/kraken.sh
fi
EOF
        chown "$KUSER:$KGROUP" "$KHOME/.bashrc"
    fi

    install -m 0644 "$ROOT/desktop/xsessions/kraken-i3.desktop" /usr/share/xsessions/kraken-i3.desktop
    install -d -m 0755 /etc/lightdm/lightdm.conf.d
    sed "s/@KRAKEN_USER@/$KUSER/" "$ROOT/desktop/lightdm/60-kraken.conf" \
        >/etc/lightdm/lightdm.conf.d/60-kraken.conf
    chmod 0644 /etc/lightdm/lightdm.conf.d/60-kraken.conf

    log "rendering the wallpaper"
    if command -v rsvg-convert >/dev/null 2>&1; then
        rsvg-convert -w 1600 -h 900 "$ROOT/desktop/wallpaper/kraken.svg" \
            -o /usr/share/kraken/wallpaper.png
    elif command -v inkscape >/dev/null 2>&1; then
        inkscape "$ROOT/desktop/wallpaper/kraken.svg" \
            --export-type=png --export-filename=/usr/share/kraken/wallpaper.png \
            --export-width=1600 --export-height=900 >/dev/null 2>&1
    else
        warn "no SVG renderer; install librsvg2-bin and re-run for a PNG wallpaper"
    fi
    if [[ -f /usr/share/kraken/wallpaper.png ]]; then
        chmod 0644 /usr/share/kraken/wallpaper.png
    fi

    log "installing Nerd Font (glyph fallback for polybar/alacritty)"
    if ! fc-list 2>/dev/null | grep -qi 'JetBrainsMono Nerd Font'; then
        font_tmp="$(mktemp -d)"
        if curl -fsSL --retry 2 --max-time 120 \
            -o "$font_tmp/font.zip" \
            "https://github.com/ryanoasis/nerd-fonts/releases/download/v3.4.0/JetBrainsMono.zip" \
            || curl -fsSL --retry 2 --max-time 120 \
                -o "$font_tmp/font.zip" \
                "https://github.com/ryanoasis/nerd-fonts/releases/latest/download/JetBrainsMono.zip"; then
            install -d -m 0755 /usr/local/share/fonts/JetBrainsMonoNerd
            if unzip -q -o "$font_tmp/font.zip" -d /usr/local/share/fonts/JetBrainsMonoNerd; then
                fc-cache -f >/dev/null 2>&1 || true
            else
                warn "could not unpack the Nerd Font archive"
            fi
        else
            warn "Nerd Font download failed; using fonts-jetbrains-mono fallback"
        fi
        rm -rf "$font_tmp"
    fi

    if [[ "$(readlink -f /etc/systemd/system/default.target 2>/dev/null)" != *graphical.target ]]; then
        systemctl set-default graphical.target >/dev/null 2>&1 || warn "could not set graphical.target"
    fi
    systemctl enable lightdm.service >/dev/null 2>&1 || warn "could not enable lightdm"
fi

# ---------------------------------------------------------------------- docs
# Kept outside the desktop block: the guide is what you reach for when the
# graphical session is the thing that broke.
if [[ -d "$ROOT/docs" ]]; then
    log "installing the user guide and hotkey sheet"
    install -d -m 0755 /usr/share/kraken
    install -m 0644 "$ROOT/docs/USER-GUIDE.md" /usr/share/kraken/USER-GUIDE.md
    install -m 0644 "$ROOT/docs/HOTKEYS.md" /usr/share/kraken/HOTKEYS.md
    install -m 0644 -o "$KUSER" -g "$KGROUP" \
        "$ROOT/docs/USER-GUIDE.md" "$KHOME/KRAKEN-USER-GUIDE.md"
    install -m 0644 -o "$KUSER" -g "$KGROUP" \
        "$ROOT/docs/HOTKEYS.md" "$KHOME/KRAKEN-HOTKEYS.md"
    if [[ -d /boot/firmware ]]; then
        install -m 0644 "$ROOT/docs/USER-GUIDE.md" /boot/firmware/KRAKEN-USER-GUIDE.md
        install -m 0644 "$ROOT/docs/HOTKEYS.md" /boot/firmware/KRAKEN-HOTKEYS.md
    fi
fi

# -------------------------------------------------------------------- finish
if [[ $LIVE -eq 1 && $SKIP_PACKAGES -eq 0 ]]; then
    warn "not starting kraken automatically: it takes over wlan0 and would drop an SSH session"
    warn "reboot, or run: sudo systemctl start kraken"
fi

if [[ $CLEAN -eq 1 ]]; then
    apt-get clean >/dev/null 2>&1 || true
    rm -rf /var/lib/apt/lists/* 2>/dev/null || true
fi

log "done"
cat <<EOF

  dashboard   http://127.0.0.1:8080/   (token required)
  token       sudo cat /etc/kraken/api.token
  config      /etc/kraken/kraken.toml
  service     systemctl status kraken
  doctor      kraken doctor
  desktop     reboot, or: systemctl restart lightdm

  The desktop user is '$KUSER'. SSID and passphrase are in the [ap] section of
  the config; change them before using this anywhere near other people.

EOF
