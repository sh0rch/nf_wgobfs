#!/usr/bin/env bash
set -e

# ---------------------------------------------------
#  1) Retrieve the IP of the peer server (WireGuard) from the environment.
#    This is the internal WG address that should be filtered.
# ---------------------------------------------------
if [ -z "$WG_PEER_IP" ]; then
  echo "ERROR: WG_PEER_IP is not set. Exiting."
  exit 1
fi

# ---------------------------------------------------
#  2) iptables rules to use with nf_wgobfs filter
# ---------------------------------------------------
iptables -t raw -I PREROUTING -i eth0 -p udp -s $WG_PEER_IP --sport 51820 --dport 51820 -j NFQUEUE --queue-num 0
iptables -t raw -I OUTPUT -o eth0 -p udp -d $WG_PEER_IP --sport 51820 --dport 51820 -j NFQUEUE --queue-num 1

# ---------------------------------------------------
#  3) Run nf_wgobfs to consume from NFQUEUE 0
#    If you want it to run alongside this container,
#    uncomment the following line:
# ---------------------------------------------------
/usr/bin/nf_wgobfs &

# ---------------------------------------------------
#  4) Pass control to the built-in WireGuard init
# ---------------------------------------------------
exec /init
