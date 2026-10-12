# Build from the directory that holds the sibling repos the module replaces
# (channel-go, hub-service-go, hub-net-node, hub-net):
#   docker build -f hub-net/agent/Dockerfile -t hub-net .
FROM golang:1.26-bookworm AS build

WORKDIR /src
COPY channel-go /src/channel-go
COPY hub-service-go /src/hub-service-go
COPY hub-net-node /src/hub-net-node
COPY hub-net/agent /src/hub-net/agent

WORKDIR /src/hub-net/agent
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.buildVersion=${VERSION}" \
    -o /out/hub-net ./cmd/hub-net

FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        conntrack \
        iproute2 \
        nftables \
        systemd-resolved \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/hub-net /run/hub-net \
    && chmod 0700 /var/lib/hub-net \
    && chmod 0755 /run/hub-net

COPY --from=build /out/hub-net /usr/local/bin/hub-net

LABEL org.opencontainers.image.title="hub-net" \
      org.opencontainers.image.description="Privileged Hub Network WireGuard agent"

VOLUME ["/var/lib/hub-net"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/hub-net"]
# The command socket stays in the state dir: /run/hub-net/agent.sock is the
# local agent socket hub-pro uses to prove the hub host's agent.
CMD ["-state-dir", "/var/lib/hub-net"]
