#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/verified-download.sh"
GEO_DIR="${GEO_DIR:-/opt/vpsentinel/static/geo}"
mkdir -p "$GEO_DIR"
# Mutable latest releases are not accepted without trusted checksums.
verified_download "${GEOSITE_URL:?Set a pinned GEOSITE_URL}" "${GEOSITE_SHA256:?Set GEOSITE_SHA256}" "$GEO_DIR/geosite.dat"
verified_download "${GEOIP_URL:?Set a pinned GEOIP_URL}" "${GEOIP_SHA256:?Set GEOIP_SHA256}" "$GEO_DIR/geoip.dat"
verified_download "${COUNTRY_URL:?Set a pinned COUNTRY_URL}" "${COUNTRY_SHA256:?Set COUNTRY_SHA256}" "$GEO_DIR/country.mmdb"
