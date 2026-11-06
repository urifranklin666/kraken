#!/usr/bin/env bash
# Launch (or restart) the KRAKEN waybar.
set -euo pipefail

CONFIG="${WAYBAR_CONFIG:-$HOME/.config/waybar/config.jsonc}"
STYLE="${WAYBAR_STYLE:-$HOME/.config/waybar/style.css}"
LOG_DIR="${XDG_CACHE_HOME:-$HOME/.cache}"
LOG="$LOG_DIR/waybar.log"
mkdir -p "$LOG_DIR"

pkill -x waybar >/dev/null 2>&1 || true
for _ in $(seq 1 20); do
    pgrep -x waybar >/dev/null || break
    sleep 0.1
done

nohup waybar -c "$CONFIG" -s "$STYLE" >"$LOG" 2>&1 &
disown || true
