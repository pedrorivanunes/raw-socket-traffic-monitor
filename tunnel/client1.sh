#!/bin/sh
# Bring up a client end of the tunnel and send everything through it.
#
# The tunnel process runs this itself, right after it creates tun0. The only
# difference between the two client scripts is the address on the last line of
# this block.

set -eu

TUN_ADDR=172.31.66.101/24
GATEWAY=172.31.66.1

ip link set tun0 mtu 1472 up
ip address replace "$TUN_ADDR" dev tun0

# Drop whatever default route exists and point it at the tunnel instead, so all
# outbound traffic reaches the Internet through the proxy -- which is the whole
# point: that is where the monitor can see it. The peer stays reachable because
# it sits on the directly connected network the tunnel rides on.
ip route del default 2>/dev/null || true
ip route add default via "$GATEWAY" dev tun0

echo "client1.sh: tun0 is up on $TUN_ADDR, default route via $GATEWAY"
