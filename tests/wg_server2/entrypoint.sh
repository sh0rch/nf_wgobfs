#!/usr/bin/env bash
set -e

# ---------------------------------------------------
#  1) Load kernel modules for nfqueue / nftables
# ---------------------------------------------------
modprobe nf_tables       || true
modprobe nfnetlink_queue || true

# ---------------------------------------------------
#  2) Retrieve the IP of the peer server (WireGuard) from the environment.
#    This is the internal WG address that should be filtered.
# ---------------------------------------------------
if [ -z "$WG_PEER_IP" ]; then
  echo "ERROR: WG_PEER_IP is not set. Exiting."
  exit 1
fi

# ---------------------------------------------------
#  3) Clear any existing ruleset, then create a new “inet filter” table
# ---------------------------------------------------
nft flush ruleset
nft add table inet filter
nft 'add chain inet filter prerouting { type filter hook prerouting priority 0; }'
nft 'add chain inet filter output    { type filter hook output    priority 0; }'

# ---------------------------------------------------
#  4) Add rules: capture **only** UDP packets
#    within the wg0 tunnel between “this” server and the peer server
# ---------------------------------------------------
#
#   a) prerouting  iifname "wg0" ip protocol udp ip saddr WG_PEER_IP → NFQUEUE
#      (all incoming UDP from the peer inside wg0)
#
#   b) output      oifname "wg0" ip protocol udp ip daddr WG_PEER_IP → NFQUEUE
#      (all outgoing UDP to the peer inside wg0)
#
nft add rule inet filter prerouting  iifname "wg0" ip protocol udp ip saddr "$WG_PEER_IP" queue num 0 bypass
nft add rule inet filter output     oifname "wg0" ip protocol udp ip daddr "$WG_PEER_IP" queue num 0 bypass

# ---------------------------------------------------
#  5) (Optional) Run nf_wgobfs to consume from NFQUEUE 0
#    If you want it to run alongside this container,
#    uncomment the following line:
# ---------------------------------------------------
/usr/bin/nf_wgobfs &

# ---------------------------------------------------
#  6) Pass control to the built-in WireGuard init
# ---------------------------------------------------
exec /init
