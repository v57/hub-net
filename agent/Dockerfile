FROM golang:1.25-bookworm AS build

WORKDIR /src
COPY hub-net/channel-go /src/hub-net/channel-go
COPY hub-net/hub-service-go /src/hub-net/hub-service-go
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
CMD ["-state-dir", "/var/lib/hub-net", "-socket", "/run/hub-net/agent.sock"]
