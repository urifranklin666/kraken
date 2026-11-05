#!/usr/bin/env bash
# KRAKEN USB builder — writes Raspberry Pi OS to a USB disk, expands the root
# filesystem, creates the desktop user, and runs install.sh inside a chroot.
#
#   sudo ./provision-usb.sh --device /dev/sda
#   sudo ./provision-usb.sh --image-file build/kraken-16g.img --size 16G --compress
#
# The target disk is erased. The script refuses the disk that hosts / and
# requires the device name to be typed unless --yes is given.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMG_URL="${KRAKEN_IMAGE_URL:-https://downloads.raspberrypi.com/raspios_lite_arm64/images/raspios_lite_arm64-2026-10-06/2026-10-06-raspios-trixie-arm64-lite.img.xz}"
IMG_NAME="$(basename "$IMG_URL")"

DEV=""
IMAGE_FILE=""
IMAGE_SIZE="16G"
COMPRESS=0
KUSER="${SUDO_USER:-}"
if [[ -z "$KUSER" || "$KUSER" == "root" ]]; then
    KUSER="$(getent passwd 1000 | cut -d: -f1 || true)"
fi
KHOST="kraken"
WITH_MITM=1
CACHE="${KRAKEN_CACHE:-}"
KEEP_DOWNLOAD=0
SKIP_DOWNLOAD=0
ASSUME_YES=0
DRY_RUN=0
ALLOW_SMALL=0
ALLOW_NON_USB=0
EEPROM_USB_FIRST=0

log()  { printf '\033[38;5;117m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[38;5;179m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[38;5;203m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
usage: sudo ./provision-usb.sh --device /dev/sdX [options]
       sudo ./provision-usb.sh --image-file FILE [--size 16G] [options]

  --device PATH        USB block device to erase (e.g. /dev/sda)
  --image-file PATH    build a disk image instead of writing a USB device
  --size SIZE          image size when --image-file is used (default 16G)
  --compress           xz-compress the finished image (keeps the raw image)
  --user NAME          desktop user (default: $SUDO_USER or uid 1000)
  --hostname NAME      hostname (default: kraken)
  --no-mitm            skip bettercap in the target install
  --cache DIR          directory for the downloaded image
  --keep-download      keep the .img.xz in the cache after provisioning
  --skip-download      use an image already in the cache
  --eeprom-usb-first   set the Pi 4 boot order to USB before SD (live only)
  --allow-small        allow a target smaller than 32 GiB
  --allow-non-usb      allow a non-USB block device
  --yes                skip the typed device-name confirmation
  --dry-run            print the plan without downloading or writing
  -h, --help
EOF
}

while (($#)); do
    case "$1" in
        --device) DEV="${2:?--device needs a path}"; shift ;;
        --image-file) IMAGE_FILE="${2:?--image-file needs a path}"; shift ;;
        --size) IMAGE_SIZE="${2:?--size needs a value}"; shift ;;
        --compress) COMPRESS=1 ;;
        --user) KUSER="${2:?--user needs a name}"; shift ;;
        --hostname) KHOST="${2:?--hostname needs a name}"; shift ;;
        --no-mitm) WITH_MITM=0 ;;
        --cache) CACHE="${2:?--cache needs a path}"; shift ;;
        --keep-download) KEEP_DOWNLOAD=1 ;;
        --skip-download) SKIP_DOWNLOAD=1 ;;
        --eeprom-usb-first) EEPROM_USB_FIRST=1 ;;
        --allow-small) ALLOW_SMALL=1 ;;
        --allow-non-usb) ALLOW_NON_USB=1 ;;
        --yes) ASSUME_YES=1 ;;
        --dry-run) DRY_RUN=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done

[[ "$(id -u)" -eq 0 ]] || die "run as root (sudo ./provision-usb.sh)"
[[ -n "$KUSER" ]] || die "cannot determine the desktop user; pass --user NAME"
[[ "$KUSER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "invalid user name: $KUSER"
[[ "$KHOST" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] || die "invalid hostname: $KHOST"
[[ -z "$DEV" || -z "$IMAGE_FILE" ]] || die "use either --device or --image-file, not both"
[[ -n "$DEV" || -n "$IMAGE_FILE" ]] || { usage; exit 1; }
[[ -z "$IMAGE_FILE" || $EEPROM_USB_FIRST -eq 0 ]] || die "--eeprom-usb-first only applies to --device"

for tool in parted partprobe e2fsck resize2fs curl xz sha256sum lsblk findmnt udevadm wipefs numfmt partx; do
    command -v "$tool" >/dev/null || die "missing host tool: $tool"
done

MNT=""
R=""
BOOT=""
LOOP_ACTIVE=0
UDISKS_STOPPED=0

cleanup() {
    set +e
    if [[ -n "$R" && -d "$R" ]]; then
        umount -R "$R" 2>/dev/null
        rmdir "$MNT" 2>/dev/null
    fi
    if [[ $LOOP_ACTIVE -eq 1 && -n "$DEV" ]]; then
        losetup -d "$DEV" 2>/dev/null
    fi
    if [[ $UDISKS_STOPPED -eq 1 ]]; then
        systemctl start udisks2 2>/dev/null
    fi
}
trap cleanup EXIT

# ------------------------------------------------------------------- cache
if [[ -z "$CACHE" ]]; then
    for candidate in /dev/shm /var/tmp "${HOME}/.cache"; do
        [[ -d "$candidate" ]] || continue
        avail="$(df -Pk "$candidate" | awk 'NR==2{print $4}')"
        if (( avail > 900000 )); then
            CACHE="$candidate/kraken-image"
            break
        fi
    done
fi
[[ -n "$CACHE" ]] || die "no cache directory with ~1 GB free; pass --cache DIR"
mkdir -p "$CACHE"
XZ_FILE="$CACHE/$IMG_NAME"
SHA_FILE="$CACHE/$IMG_NAME.sha256"

# --------------------------------------------------------------- target checks
if [[ -n "$IMAGE_FILE" ]]; then
    IMAGE_FILE="$(realpath -m "$IMAGE_FILE")"
    [[ ! -e "$IMAGE_FILE" ]] || die "$IMAGE_FILE already exists (remove it first)"
    [[ "$IMAGE_SIZE" =~ ^[0-9]+[GgMm]$ ]] || die "--size must look like 16G or 8192M"
    mkdir -p "$(dirname "$IMAGE_FILE")"
    AVAIL_KB="$(df -Pk "$(dirname "$IMAGE_FILE")" | awk 'NR==2{print $4}')"
    NEED_KB=$((6 * 1024 * 1024))
    (( AVAIL_KB > NEED_KB )) || die "image-file mode needs about 6 GB free in $(dirname "$IMAGE_FILE"); use --device instead"
else
    [[ -b "$DEV" ]] || die "not a block device: $DEV"
    DEV="$(readlink -f "$DEV")"
    [[ "$(lsblk -dno TYPE "$DEV")" == "disk" ]] || die "refusing a partition; pass the whole disk (e.g. /dev/sda)"
    TRAN="$(lsblk -dno TRAN "$DEV" | tr -d ' ')"
    if [[ "$TRAN" != "usb" && $ALLOW_NON_USB -eq 0 ]]; then
        die "$DEV is not on the USB transport (TRAN=$TRAN); use --allow-non-usb to override"
    fi
    SIZE_BYTES="$(blockdev --getsize64 "$DEV")"
    if (( SIZE_BYTES < 32 * 1024 * 1024 * 1024 && ALLOW_SMALL == 0 )); then
        die "$DEV is smaller than 32 GiB; use --allow-small to override"
    fi
    ROOT_SRC="$(findmnt -n -o SOURCE /)"
    ROOT_DISK="$(lsblk -no PKNAME "$ROOT_SRC" 2>/dev/null | head -1 || true)"
    if [[ -n "$ROOT_DISK" && "/dev/$ROOT_DISK" == "$DEV" ]]; then
        die "$DEV holds the running root filesystem"
    fi
    if [[ -z "$ROOT_DISK" && ( "$ROOT_SRC" == "$DEV"* ) ]]; then
        die "$DEV holds the running root filesystem"
    fi
fi

echo
if [[ -n "$IMAGE_FILE" ]]; then
    echo "  target image : $IMAGE_FILE ($IMAGE_SIZE, sparse + loop device)"
else
    lsblk -o NAME,SIZE,TYPE,TRAN,RM,MODEL,SERIAL,MOUNTPOINTS "$DEV"
    echo
    echo "  target disk  : $DEV  ($(numfmt --to=iec "$SIZE_BYTES"))"
fi
echo "  hostname     : $KHOST"
echo "  desktop user : $KUSER"
echo "  base image   : $IMG_NAME"
echo "  image cache  : $CACHE"
echo "  mitm package : $([[ $WITH_MITM -eq 1 ]] && echo bettercap || echo skipped)"
echo

if [[ $DRY_RUN -eq 1 ]]; then
    log "dry run: no download, no writes, no mounts"
    exit 0
fi

if [[ $ASSUME_YES -eq 0 ]]; then
    if [[ -n "$IMAGE_FILE" ]]; then
        read -r -p "Create and provision this image? [y/N] " answer
        [[ "$answer" =~ ^[Yy]$ ]] || die "cancelled"
    else
        echo "ALL DATA ON $DEV WILL BE DESTROYED."
        read -r -p "Type the device name (${DEV##*/}) to continue: " answer
        [[ "$answer" == "${DEV##*/}" ]] || die "cancelled"
    fi
fi

# ------------------------------------------------------------------ download
download_image() {
    if [[ -s "$XZ_FILE" ]]; then
        log "using cached image: $XZ_FILE"
    else
        [[ $SKIP_DOWNLOAD -eq 0 ]] || die "--skip-download was given but $XZ_FILE is missing"
        log "downloading $(numfmt --to=iec 550466056) image (this can take a while)"
        curl -fL --retry 3 --retry-delay 3 -C - -o "$XZ_FILE.part" "$IMG_URL"
        mv "$XZ_FILE.part" "$XZ_FILE"
    fi
    if [[ $SKIP_DOWNLOAD -eq 0 || ! -s "$SHA_FILE" ]]; then
        curl -fsSL --retry 3 -o "$SHA_FILE" "$IMG_URL.sha256" || warn "could not download the checksum file"
    fi
    if [[ -s "$SHA_FILE" ]]; then
        expected="$(awk 'NR==1{print $1}' "$SHA_FILE")"
        actual="$(sha256sum "$XZ_FILE" | awk '{print $1}')"
        [[ -n "$expected" && "$expected" == "$actual" ]] || die "checksum mismatch for $XZ_FILE"
        log "checksum verified"
    else
        warn "no checksum available; continuing with an unverified image"
    fi
}

download_image

# ---------------------------------------------------------------- automount
# A running udisks daemon will remount fresh partitions between parted, e2fsck
# and mount. Stop it for the duration; the cleanup trap restarts it.
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet udisks2 2>/dev/null; then
    log "pausing udisks2 to prevent automount races"
    if systemctl stop udisks2 2>/dev/null; then
        UDISKS_STOPPED=1
    fi
fi

# --------------------------------------------------------------------- write
if [[ -n "$IMAGE_FILE" ]]; then
    log "creating sparse image $IMAGE_FILE"
    truncate -s "$IMAGE_SIZE" "$IMAGE_FILE"
    DEV="$(losetup -fP --show "$IMAGE_FILE")"
    LOOP_ACTIVE=1
    log "attached $DEV"
else
    mapfile -t mounts < <(lsblk -lnpo MOUNTPOINT "$DEV" | sed '/^[[:space:]]*$/d')
    for mp in "${mounts[@]}"; do
        log "unmounting $mp"
        umount "$mp" || die "could not unmount $mp"
    done
    for part in $(lsblk -lnpo NAME,FSTYPE "$DEV" | awk '$2=="swap"{print $1}'); do
        swapoff "$part" || true
    done
    log "erasing signatures on $DEV"
    wipefs -a "$DEV" >/dev/null
fi

log "writing Raspberry Pi OS (streaming xz, no temporary image)"
xz -dc "$XZ_FILE" | dd of="$DEV" bs=4M conv=fsync status=progress
sync
partprobe "$DEV" 2>/dev/null || true
udevadm settle 2>/dev/null || true

if [[ $LOOP_ACTIVE -eq 1 ]]; then
    # Re-attach so the kernel reads the freshly written partition table.
    losetup -d "$DEV" 2>/dev/null || true
    DEV="$(losetup -fP --show "$IMAGE_FILE")"
    udevadm settle 2>/dev/null || true
fi

part_dev() {
    if [[ "$DEV" =~ [0-9]$ ]]; then
        printf '%sp%s\n' "$DEV" "$1"
    else
        printf '%s%s\n' "$DEV" "$1"
    fi
}
P1="$(part_dev 1)"
P2="$(part_dev 2)"

for _ in $(seq 1 40); do
    [[ -b "$P1" && -b "$P2" ]] && break
    partprobe "$DEV" 2>/dev/null || true
    partx -u "$DEV" 2>/dev/null || true
    sleep 0.5
done
[[ -b "$P1" && -b "$P2" ]] || die "partitions $P1 and $P2 did not appear"

# udisks may auto-mount the fresh partitions on a running desktop; free them.
mapfile -t mounts < <(lsblk -lnpo MOUNTPOINT "$DEV" | sed '/^[[:space:]]*$/d')
for mp in "${mounts[@]}"; do
    umount "$mp" 2>/dev/null || die "could not unmount auto-mounted $mp"
done

log "expanding the root partition"
parted -s "$DEV" resizepart 2 100%
partprobe "$DEV" 2>/dev/null || true
udevadm settle 2>/dev/null || true
partx -u "$DEV" 2>/dev/null || true

if [[ $LOOP_ACTIVE -eq 1 ]]; then
    losetup -d "$DEV" 2>/dev/null || true
    DEV="$(losetup -fP --show "$IMAGE_FILE")"
    P1="$(part_dev 1)"
    P2="$(part_dev 2)"
    udevadm settle 2>/dev/null || true
    for _ in $(seq 1 20); do
        [[ -b "$P1" && -b "$P2" ]] && break
        sleep 0.5
    done
fi

rc=0
e2fsck -f -y "$P2" >/dev/null 2>&1 || rc=$?
(( rc <= 1 )) || die "e2fsck failed on $P2 (exit $rc)"
resize2fs "$P2" >/dev/null

# --------------------------------------------------------------------- mount
MNT="$(mktemp -d /mnt/kraken-provision.XXXXXX)"
R="$MNT/root"
RESOLV_LINK=""
RESOLV_BACKUP=0

mkdir -p "$R"
mount "$P2" "$R"
if [[ -d "$R/boot/firmware" ]]; then
    BOOT="$R/boot/firmware"
else
    BOOT="$R/boot"
fi
mkdir -p "$BOOT"
mount "$P1" "$BOOT"

for dir in dev dev/pts proc sys; do
    mkdir -p "$R/$dir"
    mount --bind "/$dir" "$R/$dir"
done

if [[ -L "$R/etc/resolv.conf" ]]; then
    RESOLV_LINK="$(readlink "$R/etc/resolv.conf")"
elif [[ -f "$R/etc/resolv.conf" ]]; then
    cp -a "$R/etc/resolv.conf" "$R/etc/resolv.conf.kraken-bak"
    RESOLV_BACKUP=1
fi
rm -f "$R/etc/resolv.conf"
{
    grep -E '^nameserver[[:space:]]+' /etc/resolv.conf | grep -vE '127\.0\.0\.(1|53)' || true
    echo "nameserver 1.1.1.1"
    echo "nameserver 9.9.9.9"
} >"$R/etc/resolv.conf"
chmod 0644 "$R/etc/resolv.conf"

log "copying the KRAKEN source into the target"
install -d -m 0755 "$R/opt/kraken-src"
tar -C "$ROOT" --exclude=.git --exclude=image --exclude=tools \
    --exclude='__pycache__' --exclude='*.pyc' \
    -cf - . | tar -C "$R/opt/kraken-src" -xf -

# The RT5370 needs rt2870.bin; take it from the host so wlan1 works even when
# the target's non-free firmware package is unavailable.
for fw in rt2870.bin rt3290.bin; do
    if [[ -f "/lib/firmware/$fw" ]]; then
        install -D -m 0644 "/lib/firmware/$fw" "$R/lib/firmware/$fw"
    fi
done

# ----------------------------------------------------------------- target user
CREATED_USER=0
GENERATED_PASSWORD=""
if ! chroot "$R" id -u "$KUSER" >/dev/null 2>&1; then
    log "creating user $KUSER"
    chroot "$R" useradd -m -s /bin/bash "$KUSER"
    CREATED_USER=1
    HASH="$(getent shadow "$KUSER" | cut -d: -f2 || true)"
    case "$HASH" in
        \$*) ;;
        *)
            GENERATED_PASSWORD="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-16)"
            HASH="$(openssl passwd -6 "$GENERATED_PASSWORD")"
            ;;
    esac
    printf '%s:%s\n' "$KUSER" "$HASH" | chroot "$R" chpasswd -e
    unset HASH
fi

for group in sudo adm dialout audio video plugdev games users input render netdev bluetooth; do
    chroot "$R" getent group "$group" >/dev/null 2>&1 || continue
    chroot "$R" usermod -aG "$group" "$KUSER"
done

if [[ -s "/home/$KUSER/.ssh/authorized_keys" ]]; then
    log "copying SSH authorized_keys"
    UID_T="$(chroot "$R" id -u "$KUSER")"
    GID_T="$(chroot "$R" id -g "$KUSER")"
    install -d -m 0700 -o "$UID_T" -g "$GID_T" "$R/home/$KUSER/.ssh"
    install -m 0600 -o "$UID_T" -g "$GID_T" \
        "/home/$KUSER/.ssh/authorized_keys" "$R/home/$KUSER/.ssh/authorized_keys"
fi

if [[ -L /etc/localtime ]]; then
    TZ_NAME="$(readlink /etc/localtime | sed 's#.*/zoneinfo/##')"
    if [[ -n "$TZ_NAME" && -e "$R/usr/share/zoneinfo/$TZ_NAME" ]]; then
        printf '%s\n' "$TZ_NAME" >"$R/etc/timezone"
        ln -sfn "/usr/share/zoneinfo/$TZ_NAME" "$R/etc/localtime"
    fi
fi

REG_DOMAIN="$(python3 - "$ROOT/config/kraken.toml" <<'PY'
import sys
try:
    import tomllib
    with open(sys.argv[1], "rb") as handle:
        print(tomllib.load(handle).get("radio", {}).get("reg_domain", "US"))
except Exception:
    print("US")
PY
)"
install -d -m 0755 "$R/etc/default"
printf 'REGDOMAIN=%s\n' "$REG_DOMAIN" >"$R/etc/default/crda"

if ! chroot "$R" python3 -c 'import socket; socket.getaddrinfo("deb.debian.org", 443)' >/dev/null 2>&1; then
    warn "DNS inside the chroot is not resolving; apt may fail"
fi

# ----------------------------------------------------------------- install
log "running install.sh inside the target (this is the long step)"
chroot "$R" /usr/bin/env \
    DEBIAN_FRONTEND=noninteractive \
    HOME=/root \
    LANG=C.UTF-8 \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    /bin/bash /opt/kraken-src/install.sh --image \
        --user "$KUSER" --home "/home/$KUSER" --hostname "$KHOST" \
        $([[ $WITH_MITM -eq 1 ]] && echo --with-mitm || echo --no-mitm)

# systemctl enable works offline, but make the critical links explicit anyway.
mkdir -p "$R/etc/systemd/system/multi-user.target.wants"
ln -sfn /etc/systemd/system/kraken.service \
    "$R/etc/systemd/system/multi-user.target.wants/kraken.service"
ln -sfn /etc/systemd/system/kraken-firstboot.service \
    "$R/etc/systemd/system/multi-user.target.wants/kraken-firstboot.service"
for unit in "$R/usr/lib/systemd/system/lightdm.service" "$R/lib/systemd/system/lightdm.service"; do
    if [[ -f "$unit" ]]; then
        ln -sfn "/${unit#"$R"/}" "$R/etc/systemd/system/display-manager.service"
        break
    fi
done
if [[ -f "$R/usr/lib/systemd/system/graphical.target" ]]; then
    ln -sfn /usr/lib/systemd/system/graphical.target "$R/etc/systemd/system/default.target"
fi
for unit in hostapd.service dnsmasq.service bettercap.service userconfig.service; do
    ln -sfn /dev/null "$R/etc/systemd/system/$unit"
done

for unit in "$R/usr/lib/systemd/system/ssh.service" "$R/lib/systemd/system/ssh.service"; do
    if [[ -f "$unit" ]]; then
        ln -sfn "/${unit#"$R"/}" "$R/etc/systemd/system/multi-user.target.wants/ssh.service"
        break
    fi
done
touch "$BOOT/ssh"

if [[ ! -x "$R/usr/bin/i3" ]]; then
    warn "i3 is missing in the target; the desktop will not start"
fi
if [[ ! -x "$R/usr/sbin/lightdm" ]]; then
    warn "lightdm is missing in the target; boot to a console instead"
fi

if [[ -f "$BOOT/config.txt" ]] && ! grep -q '^disable_splash=1' "$BOOT/config.txt"; then
    printf '\n# KRAKEN: skip the rainbow splash\n' >>"$BOOT/config.txt"
    printf 'disable_splash=1\n' >>"$BOOT/config.txt"
fi
if [[ -f "$BOOT/cmdline.txt" ]] && ! grep -qw quiet "$BOOT/cmdline.txt"; then
    sed -i '1s/[[:space:]]*$/ quiet loglevel=3/' "$BOOT/cmdline.txt"
fi

log "verifying the target install"
[[ -x "$R/usr/local/bin/kraken" ]] || die "CLI wrapper missing in the target"
[[ -s "$R/etc/kraken/kraken.toml" ]] || die "config missing in the target"
chroot "$R" python3 -c 'import tomllib; tomllib.load(open("/etc/kraken/kraken.toml", "rb"))' \
    || die "the target config does not parse"
chroot "$R" /usr/local/bin/kraken --help >/dev/null || die "the CLI wrapper does not run"

# --------------------------------------------------------------- sanitize
: >"$R/etc/machine-id"
chmod 0444 "$R/etc/machine-id"
rm -f "$R"/etc/ssh/ssh_host_*
find "$R/var/log" -type f -delete 2>/dev/null || true
find "$R/var/lib/apt/lists" -mindepth 1 -delete 2>/dev/null || true
find "$R/var/cache/apt/archives" -name '*.deb' -delete 2>/dev/null || true

if [[ -n "$RESOLV_LINK" ]]; then
    rm -f "$R/etc/resolv.conf"
    ln -s "$RESOLV_LINK" "$R/etc/resolv.conf"
elif [[ $RESOLV_BACKUP -eq 1 ]]; then
    mv "$R/etc/resolv.conf.kraken-bak" "$R/etc/resolv.conf"
else
    rm -f "$R/etc/resolv.conf"
fi

sync
log "unmounting the target"
umount -R "$R" || die "could not unmount the target cleanly"
# The bind and boot mounts leave empty directories behind (root/, boot/firmware/).
find "$MNT" -mindepth 1 -depth -type d -empty -delete 2>/dev/null || true
rmdir "$MNT" 2>/dev/null || warn "left behind $MNT (not empty)"
MNT=""
R=""

if [[ $LOOP_ACTIVE -eq 1 ]]; then
    losetup -d "$DEV"
    DEV=""
fi
if [[ $UDISKS_STOPPED -eq 1 ]]; then
    systemctl start udisks2 2>/dev/null || true
    UDISKS_STOPPED=0
fi
trap - EXIT

# ---------------------------------------------------------------- boot order
if [[ $EEPROM_USB_FIRST -eq 1 ]]; then
    if command -v rpi-eeprom-config >/dev/null 2>&1; then
        log "setting the Pi 4 boot order to USB first (falls back to SD)"
        eeprom_tmp="$(mktemp)"
        rpi-eeprom-config >"$eeprom_tmp"
        if grep -q '^BOOT_ORDER=' "$eeprom_tmp"; then
            sed -i 's/^BOOT_ORDER=.*/BOOT_ORDER=0xf14/' "$eeprom_tmp"
        else
            printf 'BOOT_ORDER=0xf14\n' >>"$eeprom_tmp"
        fi
        rpi-eeprom-config --apply "$eeprom_tmp" || warn "EEPROM update failed"
        rm -f "$eeprom_tmp"
        warn "the new boot order takes effect after a power cycle"
    else
        warn "rpi-eeprom-config not found; install rpi-eeprom or set BOOT_ORDER manually"
    fi
fi

# ------------------------------------------------------------------- summary
if [[ -n "$IMAGE_FILE" ]]; then
    if [[ $COMPRESS -eq 1 ]]; then
        log "compressing the image (xz -T0 -3)"
        xz -T0 -3 -k -f "$IMAGE_FILE"
        echo
        ls -lh "$IMAGE_FILE" "$IMAGE_FILE.xz"
        sha256sum "$IMAGE_FILE.xz"
    else
        ls -lh "$IMAGE_FILE"
    fi
    echo
    if [[ $COMPRESS -eq 1 ]]; then
        echo "  Flash it with:"
        echo "    xz -dc $(basename "$IMAGE_FILE").xz | sudo dd of=/dev/sdX bs=4M conv=fsync status=progress"
        echo "    (or use Raspberry Pi Imager / balenaEtcher on the .img.xz)"
    else
        echo "  Flash it with:"
        echo "    sudo dd if=$IMAGE_FILE of=/dev/sdX bs=4M conv=fsync status=progress"
    fi
else
    echo
    log "USB provisioning complete"
    cat <<EOF

  Power off the Pi, remove the SD card (or keep it if the boot order prefers
  USB), insert the USB disk, and power on. First boot starts KRAKEN and the
  i3 desktop automatically.

  desktop login   $KUSER (autologin)
  dashboard       http://${KHOST}.local:8080/  or  http://10.13.37.1:8080/
  token           sudo cat /etc/kraken/api.token
  config          sudoedit /etc/kraken/kraken.toml
  service         systemctl status kraken

EOF
    if [[ $CREATED_USER -eq 1 && -n "$GENERATED_PASSWORD" ]]; then
        echo "  The host password hash was unavailable, so a temporary password was set:"
        echo "    $GENERATED_PASSWORD"
        echo "  Change it after the first login with: passwd"
        echo
    fi
    echo "  Change the default SSID/passphrase in the [ap] section before using this"
    echo "  anywhere near other people. Recon is passive by default; deauth and MITM"
    echo "  require --authorized and an explicit enable."
fi

if [[ $KEEP_DOWNLOAD -eq 0 && "$CACHE" == /dev/shm/* ]]; then
    rm -f "$XZ_FILE" "$SHA_FILE"
    rmdir "$CACHE" 2>/dev/null || true
fi
