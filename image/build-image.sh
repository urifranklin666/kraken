#!/usr/bin/env bash
# Build a flashable KRAKEN image with the shared provisioning pipeline.
#
#   sudo ./image/build-image.sh [OUT.img] [--size 16G] [--compress]
#
# All arguments after OUT are passed to provision-usb.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$HERE/kraken-16g.img}"
shift || true

exec "$HERE/../provision-usb.sh" --image-file "$OUT" "$@"
