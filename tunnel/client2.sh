#!/bin/sh
# The second client. Identical to client1.sh apart from the address.

set -eu

TUN_ADDR=172.31.66.102/24
GATEWAY=172.31.66.1

ip link set tun0 mtu 1472 up
ip address replace "$TUN_ADDR" dev tun0

ip route del default 2>/dev/null || true
ip route add default via "$GATEWAY" dev tun0

echo "client2.sh: tun0 is up on $TUN_ADDR, default route via $GATEWAY"
