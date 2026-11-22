#!/bin/sh
# Loads /policy/rules.nft (rendered by penenv per scan), then idles.
# Docker does not guarantee interface order, so the interface facing the scan
# network is found by its address ($GW_IP) and substituted for @INNER@.
set -e
[ -n "$GW_IP" ] || { echo "GW_IP not set" >&2; exit 1; }
INNER=$(ip -o -4 addr show | awk -v ip="$GW_IP" '{split($4, a, "/"); if (a[1] == ip) print $2}')
[ -n "$INNER" ] || { echo "no interface holds $GW_IP" >&2; exit 1; }
echo "$INNER" > /run/penenv-inner
sed "s/@INNER@/$INNER/g" /policy/rules.nft > /run/rules.nft
nft -f /run/rules.nft
echo "penenv-egress-gw ready inner=$INNER"
exec tail -f /dev/null
