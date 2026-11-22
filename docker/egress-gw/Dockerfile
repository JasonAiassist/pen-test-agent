# penenv egress gateway: the only route out of a scan's internal network.
# Enforces the per-scan allowlist with nftables in its own network namespace.
FROM alpine:3.20
RUN apk add --no-cache nftables iproute2 tcpdump
COPY gw-entry.sh /gw-entry.sh
ENTRYPOINT ["/bin/sh", "/gw-entry.sh"]
