#!/usr/bin/env bash
# Launch (or restart) the KRAKEN status bar (Waybar under Wayland, Polybar under X11).
set -euo pipefail

if [[ -n "${WAYLAND_DISPLAY:-}" ]] && [[ -x "$HOME/.config/waybar/launch.sh" ]]; then
    exec "$HOME/.config/waybar/launch.sh"
fi

CONFIG="${POLYBAR_CONFIG:-$HOME/.config/polybar/config.ini}"
LOG_DIR="${XDG_CACHE_HOME:-$HOME/.cache}"
LOG="$LOG_DIR/polybar.log"
mkdir -p "$LOG_DIR"

polybar-msg cmd quit >/dev/null 2>&1 || true
pkill -x polybar >/dev/null 2>&1 || true
for _ in $(seq 1 20); do
    pgrep -x polybar >/dev/null || break
    sleep 0.1
done

if [[ -z "${MONITOR:-}" ]]; then
    MONITOR="$(xrandr --query 2>/dev/null | awk '/ connected/{print $1; exit}')"
fi
export MONITOR="${MONITOR:-}"

nohup polybar --reload -c "$CONFIG" kraken >"$LOG" 2>&1 &
disown || true
