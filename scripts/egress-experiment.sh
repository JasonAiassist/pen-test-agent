#!/usr/bin/env bash
# T0.5 network-enforcement experiment (re-runnable).
# Builds: internal scan network + egress gateway + decoy, then proves that the
# sandbox reaches only the allowlisted target while the decoy sees zero packets.
# Run with docker access:  echo "bash scripts/egress-experiment.sh" | newgrp docker
set -u
ID=exp$$
NET=penenv-scan-$ID
SUBNET=172.31.250.0/24 GW_IP=172.31.250.2
TNET=targets_default
SANDBOX_IMG=ghcr.io/usestrix/strix-sandbox:1.4.1
TARGET_IP=$(docker inspect penenv-juice-shop --format "{{(index .NetworkSettings.Networks \"$TNET\").IPAddress}}")
POL=$(mktemp -d)
cleanup() { docker rm -f gw-$ID sb-$ID decoy-$ID >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; rm -rf "$POL"; }
trap cleanup EXIT
say() { printf '\n### %s\n' "$*"; }

docker network create --internal --subnet $SUBNET -o com.docker.network.bridge.inhibit_ipv4=true $NET >/dev/null
docker run -d --name decoy-$ID --network $TNET --entrypoint sh penenv-egress-gw:2 \
  -c 'tcpdump -n -i eth0 -w /tmp/d.pcap not arp & while :; do echo ok | nc -l -p 80; done' >/dev/null
sleep 1
DECOY_IP=$(docker inspect decoy-$ID --format "{{(index .NetworkSettings.Networks \"$TNET\").IPAddress}}")

cat > "$POL/rules.nft" <<EOF
flush ruleset
table inet penenv {
  set allow4 {
    type ipv4_addr . inet_service
    flags interval
    elements = { $TARGET_IP . 3000 }
  }
  set deny4 {
    type ipv4_addr
    flags interval
    elements = { $DECOY_IP }
  }
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ip daddr @deny4 counter drop
    ct state established,related accept
    ct status dnat iifname != "@INNER@" oifname "@INNER@" counter accept
    ip saddr $SUBNET ip daddr . tcp dport @allow4 counter accept
    counter drop
  }
  chain pre {
    type nat hook prerouting priority -100;
  }
  chain post {
    type nat hook postrouting priority 100;
    ip saddr $SUBNET oifname != "@INNER@" masquerade
    ct status dnat oifname "@INNER@" masquerade
  }
}
EOF
docker create --name gw-$ID --network $NET --ip $GW_IP --cap-add NET_ADMIN -e GW_IP=$GW_IP \
  --sysctl net.ipv4.ip_forward=1 -p 127.0.0.1::48080 -v "$POL:/policy:ro" penenv-egress-gw:2 >/dev/null
docker network connect $TNET gw-$ID
docker start gw-$ID >/dev/null; sleep 1
say "gateway"; docker logs gw-$ID

# sandbox exactly as Strix creates it: NET_ADMIN+NET_RAW, internal network only
docker run -d --name sb-$ID --network $NET --cap-add NET_ADMIN --cap-add NET_RAW \
  --entrypoint tail $SANDBOX_IMG -f /dev/null >/dev/null
say "sandbox before route (expect: no egress at all)"
docker exec sb-$ID curl -s -m 3 -o /dev/null -w "%{http_code}\n" http://$TARGET_IP:3000/ || echo "curl failed (fail-closed)"
docker exec --user root sb-$ID ip route replace default via $GW_IP
say "allowlisted target $TARGET_IP:3000 (expect 200)"
docker exec sb-$ID curl -s -m 5 -o /dev/null -w "%{http_code}\n" http://$TARGET_IP:3000/
say "allowlisted host, other port 22 (expect fail)"
docker exec sb-$ID curl -s -m 3 telnet://$TARGET_IP:22 </dev/null; echo "rc=$?"
say "decoy $DECOY_IP:80 via curl (expect fail)"
docker exec sb-$ID curl -s -m 3 http://$DECOY_IP/; echo "rc=$?"
say "decoy via nmap -sS -Pn (expect filtered)"
docker exec --user root sb-$ID nmap -sS -Pn -p 22,80,443 --max-retries 1 $DECOY_IP | grep -E "^[0-9]+/|Host"
say "internet 1.1.1.1:443 (expect fail)"
docker exec sb-$ID curl -s -m 3 -o /dev/null https://1.1.1.1/; echo "rc=$?"
say "host via internal bridge 172.31.250.1:22 (expect fail)"
docker exec sb-$ID curl -s -m 3 telnet://172.31.250.1:22 </dev/null; echo "rc=$?"
say "agent tampering as root: flush own netns, re-add direct route to decoy subnet"
docker exec --user root sb-$ID sh -c "ip route replace 172.20.0.0/16 dev eth0; ip neigh flush all" ; \
docker exec sb-$ID curl -s -m 3 http://$DECOY_IP/; echo "rc=$?"
say "host -> sandbox control channel via gateway-published port (expect 200)"
docker exec -d sb-$ID python3 -m http.server 48080
SB_IP=$(docker inspect sb-$ID --format "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}")
docker exec gw-$ID nft add rule inet penenv pre iifname != "$(docker exec gw-$ID cat /run/penenv-inner)" tcp dport 48080 dnat ip to $SB_IP:48080
HP=$(docker port gw-$ID 48080/tcp | head -1); sleep 1
curl -s -m 3 -o /dev/null -w "host->sandbox via $HP %{http_code}\n" http://$HP/ || echo "host->sandbox FAILED"
say "DNS from sandbox (expect no external resolution)"
docker exec sb-$ID getent hosts example.com || echo "no external DNS"
say "gateway counters"; docker exec gw-$ID nft list chain inet penenv forward | grep counter
say "decoy packet capture (expect 0 packets)"
docker exec decoy-$ID sh -c 'kill -INT $(pidof tcpdump); sleep 1; tcpdump -n -r /tmp/d.pcap 2>/dev/null | grep -v -e " > 224\\." -e " > 255\\." -e " > ff0" -e "IP6 fe80" | tee /dev/stderr | wc -l'
