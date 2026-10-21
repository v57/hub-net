# Linux test host for Hub Network acceptance runs on colima (see README.md).
# Binaries and sources are mounted from ~/Developer/Hub, not copied.
FROM oven/bun:1.3-debian
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates conntrack curl iproute2 iptables iputils-ping netcat-openbsd nftables procps socat tcpdump wireguard-tools \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/hub-net
