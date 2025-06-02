FROM linuxserver/wireguard

# Install only iperf3 (WireGuard is already “built into” the image)
RUN apk add --no-cache iperf3

# Run the standard linuxserver/wireguard init,
# which will automatically read /config/wg0.conf and bring up the wg0 interface
ENTRYPOINT [ "/init" ]
