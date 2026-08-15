#!/bin/sh
# Start one node of the lab.
#
#   entrypoint.sh proxy            bring up the server end and run the monitor
#   entrypoint.sh client <script>  bring up a client end and generate traffic
#
# The virtual machines this replaces each had one network card and a person
# typing commands into them. A container has neither, so the ordering the
# README describes -- tunnel first, then the monitor, then traffic -- happens
# here instead.

set -eu

# The subnet the tunnel rides on, i.e. the container network that stands in for
# the VirtualBox NAT network.
LAB_SUBNET_PREFIX="${LAB_SUBNET_PREFIX:-10.90.1.}"

# Where the monitor writes its capture files.
CAPTURE_DIR="${CAPTURE_DIR:-/capture}"

# What the clients fetch, and how often.
TRAFFIC_TARGET="${TRAFFIC_TARGET:-http://10.90.2.10/}"
TRAFFIC_INTERVAL="${TRAFFIC_INTERVAL:-5}"

log() {
    echo "[$(date '+%H:%M:%S')] $*"
}

# The proxy has two network cards and Docker does not promise which one is
# eth0, so the carrier interface is found by its address instead of guessed.
find_lab_interface() {
    ip -oneline -4 address show |
        awk -v prefix="$LAB_SUBNET_PREFIX" '$4 ~ "^" prefix { print $2; exit }'
}

wait_for_tunnel_address() {
    expected="$1"
    attempt=0

    while [ "$attempt" -lt 100 ]; do
        if ip -4 address show tun0 2>/dev/null | grep -q "$expected"; then
            return 0
        fi
        if ! pgrep -x traffic_tunnel > /dev/null 2>&1; then
            log "the tunnel process exited before tun0 came up"
            return 1
        fi
        attempt=$((attempt + 1))
        sleep 0.2
    done

    log "timed out waiting for tun0 to get $expected"
    return 1
}

ROLE="${1:-}"
[ -n "$ROLE" ] || { echo "usage: entrypoint.sh proxy|client [script]" >&2; exit 1; }
shift

LAB_INTERFACE="$(find_lab_interface)"
if [ -z "$LAB_INTERFACE" ]; then
    log "no interface found on $LAB_SUBNET_PREFIX; is the lab network attached?"
    ip -oneline -4 address show >&2
    exit 1
fi
log "carrier interface: $LAB_INTERFACE"

case "$ROLE" in
proxy)
    mkdir -p "$CAPTURE_DIR"

    log "starting the tunnel in server mode"
    traffic_tunnel "$LAB_INTERFACE" -s &

    wait_for_tunnel_address "172.31.66.1"
    log "tun0 is up; starting the monitor"

    # The monitor runs in the foreground so the container's lifetime is the
    # monitor's lifetime and `docker compose logs proxy` shows the panel.
    exec monitor tun0 --output-dir "$CAPTURE_DIR"
    ;;

client)
    SCRIPT="${1:-client1.sh}"
    case "$SCRIPT" in
    client1.sh) EXPECTED_ADDRESS="172.31.66.101" ;;
    client2.sh) EXPECTED_ADDRESS="172.31.66.102" ;;
    *) EXPECTED_ADDRESS="172.31.66." ;;
    esac

    log "starting the tunnel in client mode with $SCRIPT"
    traffic_tunnel "$LAB_INTERFACE" -c "$SCRIPT" &

    wait_for_tunnel_address "$EXPECTED_ADDRESS"
    log "tun0 is up; default route now goes through the tunnel"

    if [ "${GENERATE_TRAFFIC:-1}" = "0" ]; then
        log "traffic generation is off; idling"
        wait
        exit 0
    fi

    # Every request here leaves through tun0, crosses the tunnel, gets NATed by
    # the proxy and comes back the same way -- which is the whole point: the
    # monitor sees all of it in the clear on the proxy's tun0.
    log "fetching $TRAFFIC_TARGET every ${TRAFFIC_INTERVAL}s"
    while true; do
        if curl --silent --show-error --max-time 10 --output /dev/null "$TRAFFIC_TARGET"; then
            log "fetched $TRAFFIC_TARGET"
        else
            log "request to $TRAFFIC_TARGET failed"
        fi
        sleep "$TRAFFIC_INTERVAL"
    done
    ;;

*)
    echo "unknown role '$ROLE'; expected proxy or client" >&2
    exit 1
    ;;
esac
