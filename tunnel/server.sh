#!/bin/sh
# Bring up the server end of the tunnel: give tun0 an address, turn on
# forwarding, and NAT everything coming out of the tunnel subnet.
#
# The tunnel process runs this itself, right after it creates tun0.

set -eu

TUN_ADDR=172.31.66.1/24
TUN_SUBNET=172.31.0.0/16

ip link set tun0 mtu 1472 up
ip address replace "$TUN_ADDR" dev tun0

# In a container /proc/sys is read-only, so this is set from the outside
# instead (see the `sysctls` key in docker-compose.yml). Only complain if it is
# off and cannot be turned on -- nothing will route otherwise.
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    if ! echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null; then
        echo "server.sh: cannot enable net.ipv4.ip_forward; forwarding will not work" >&2
        exit 1
    fi
fi

# `! -o tun0` keeps the rule from masquerading traffic on its way back into the
# tunnel; without it the clients see the proxy's address instead of the remote
# host's. `-C` first so re-running this does not stack duplicate rules.
if ! iptables -t nat -C POSTROUTING -s "$TUN_SUBNET" ! -o tun0 -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s "$TUN_SUBNET" ! -o tun0 -j MASQUERADE
fi

echo "server.sh: tun0 is up on $TUN_ADDR, forwarding and NAT are on"
