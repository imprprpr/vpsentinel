#!/usr/bin/env bash
# Permit unprivileged ICMP datagram sockets for the dedicated service group.
# Keep NoNewPrivileges and the empty capability bounding set intact.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo 'Run as root.' >&2; exit 1; }
ping_gid=$(id -g vpsentinel)
# A capability-tagged system ping may fail exec under an empty bounding set.
# Install a root-owned copy without file capabilities; leave the system tool intact.
ping_tool=$(command -v ping || true)
ping_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin"
if [ -n "$ping_tool" ] && [ "$ping_tool" != "$ping_dir/ping" ]; then
    install -d -m 0755 -o root -g root "$ping_dir"
    install -m 0755 -o root -g root "$ping_tool" "$ping_dir/ping"
fi
if [ ! -r /proc/sys/net/ipv4/ping_group_range ]; then
    echo 'ICMP group sockets unavailable; latency UI will report probe unavailability.' >&2
    exit 0
fi
read -r ping_low ping_high < /proc/sys/net/ipv4/ping_group_range
if (( ping_gid >= ping_low && ping_gid <= ping_high )); then exit 0; fi
if (( ping_low <= ping_high )); then
    echo 'Existing ICMP group policy excludes vpsentinel; retained. Add its group explicitly in your host policy if required.' >&2
    exit 0
fi
# Only replace a disabled range; never broaden an existing group policy.
if ! sysctl -w "net.ipv4.ping_group_range=$ping_gid $ping_gid"; then
    echo 'Host denies ICMP group configuration; ICMP probe remains unavailable.' >&2
    exit 0
fi
install -d -m 0755 /etc/sysctl.d
ping_temp=$(mktemp /etc/sysctl.d/.vpsentinel-ping.XXXXXX)
trap 'rm -f "$ping_temp"' EXIT
printf '# Dedicated VPSentinel ICMP socket group\nnet.ipv4.ping_group_range = %s %s\n' "$ping_gid" "$ping_gid" > "$ping_temp"
chmod 0644 "$ping_temp"
mv "$ping_temp" /etc/sysctl.d/60-vpsentinel-ping.conf
