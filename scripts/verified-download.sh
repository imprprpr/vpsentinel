#!/usr/bin/env bash
# Source this file; caller supplies an independently verified SHA-256.
verified_download() {
    local url="$1" checksum="$2" output="$3" temporary
    if [[ "$url" != https://* || ! "$checksum" =~ ^[a-fA-F0-9]{64}$ ]]; then
        echo 'Provide a pinned HTTPS artifact URL and its independently verified SHA-256.' >&2
        return 1
    fi
    temporary=$(mktemp "${output}.download.XXXXXX") || return 1
    if curl --proto '=https' --proto-redir '=https' --fail --location --max-time 180 "$url" -o "$temporary" && printf '%s  %s\n' "$checksum" "$temporary" | sha256sum --check --status; then
        mv -f "$temporary" "$output"
    else
        rm -f "$temporary"
        echo 'Artifact download or checksum verification failed.' >&2
        return 1
    fi
}
