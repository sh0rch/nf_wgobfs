#############################################
# Dockerfile for wg_server1 (and similarly for wg_server2)
#############################################

# ---------------------------------------------
#  Base image: linuxserver/wireguard
#  – already includes /init, WireGuard helpers, etc.
# ---------------------------------------------
FROM linuxserver/wireguard

#############################################
# 1) Install runtime dependencies:
#    iperf3, nftables, iptables, curl, jq, etc.
#############################################
RUN apk add --no-cache \
      iperf3 \
      tcpdump
#############################################
# 2) Automatically fetch the “latest” nf_wgobfs release
#    and unpack it directly into the root (“/”)
#############################################
RUN set -eux; \
    # 2.1) Retrieve the name of the latest tag, e.g. "v0.4.1"
    latest_tag="$(curl -sL https://api.github.com/repos/sh0rch/nf_wgobfs/releases/latest \
                  | jq -r .tag_name)"; \
    version_no_v="${latest_tag#v}"; \
    # 2.2) Download the archive with prebuilt binaries and extract the entire archive into “/” 
    #      (it already contains /usr/bin/nf_wgobfs and /etc/nf_wgobfs/)
    cd /tmp; \
    curl -sL \
      "https://github.com/sh0rch/nf_wgobfs/releases/download/${latest_tag}/nf_wgobfs-${version_no_v}-x86_64.tar.gz" | \
      tar -xzf - -C /; \
    chmod +x /usr/bin/nf_wgobfs; \
    rm -rf /tmp/*

#############################################
# 3) Copy our universal entrypoint.sh
#############################################
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

#############################################
# 4) Expose the WireGuard UDP port
#############################################
EXPOSE 51820/udp

#############################################
# 5) Entrypoint
#############################################
ENTRYPOINT ["/entrypoint.sh"]
