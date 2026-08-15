#!/bin/sh
# End-to-end test of the whole lab.
#
# The unit tests prove the classifier is right about bytes handed to it. This
# proves the thing those bytes come from: it brings up the three containers,
# lets a client fetch a page through the tunnel, and then checks that the
# monitor's CSV files describe that request -- the right client address, the
# right destination, and the request line itself.
#
# Nothing here is stubbed. The tunnel really encapsulates, the proxy really
# NATs, and the monitor really reads a raw socket.
#
#   ./docker/integration-test.sh
#
# Run it from the repository root.

set -eu

CAPTURE_DIR="./capture"
NETWORK_CSV="$CAPTURE_DIR/network_layer.csv"
TRANSPORT_CSV="$CAPTURE_DIR/transport_layer.csv"
APPLICATION_CSV="$CAPTURE_DIR/application_layer.csv"

CLIENT1="172.31.66.101"
CLIENT2="172.31.66.102"
TARGET="10.90.2.10"

# Long enough for both clients to complete at least one request; they fetch
# every five seconds and the proxy has to come up healthy first.
TIMEOUT="${TIMEOUT:-90}"

failures=0

log() {
    echo "[integration] $*"
}

cleanup() {
    log "tearing the lab down"
    docker compose down --volumes --remove-orphans > /dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Wait until `pattern` shows up in `file`, or give up after TIMEOUT seconds.
wait_for() {
    file="$1"
    pattern="$2"
    what="$3"
    waited=0

    while [ "$waited" -lt "$TIMEOUT" ]; do
        if [ -f "$file" ] && grep -q "$pattern" "$file" 2>/dev/null; then
            log "found $what after ${waited}s"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done

    log "FAIL: timed out after ${TIMEOUT}s waiting for $what in $(basename "$file")"
    failures=$((failures + 1))
    return 1
}

check_contains() {
    file="$1"
    pattern="$2"
    what="$3"

    if [ -f "$file" ] && grep -q "$pattern" "$file" 2>/dev/null; then
        log "ok: $what"
    else
        log "FAIL: $what"
        failures=$((failures + 1))
    fi
}

log "starting the lab"
rm -rf "$CAPTURE_DIR"
mkdir -p "$CAPTURE_DIR"

docker compose down --volumes --remove-orphans > /dev/null 2>&1 || true
docker compose up --build --detach

# The proxy has a healthcheck, so compose has already waited for tun0 before
# starting the clients. What is left is waiting for traffic to actually flow.
log "waiting for client traffic to reach the capture (up to ${TIMEOUT}s)"

if wait_for "$APPLICATION_CSV" "GET / HTTP/1.1" "an HTTP request line"; then
    # The monitor watches tun0 on the proxy, which is upstream of the NAT, so
    # the packets it records still carry the client's own address. That is the
    # property the whole lab exists to demonstrate.
    #
    # Both clients are waited for rather than checked once: they come up
    # together but do not finish their first request at the same instant, and
    # asserting immediately after the first HTTP line appears makes the result
    # depend on which one happened to be quicker.
    wait_for "$TRANSPORT_CSV" "$CLIENT1" "client1 ($CLIENT1)"
    wait_for "$TRANSPORT_CSV" "$CLIENT2" "client2 ($CLIENT2)"

    check_contains "$NETWORK_CSV" "$TARGET" "the target ($TARGET) seen at the network layer"
    check_contains "$APPLICATION_CSV" "HTTP" "traffic classified as HTTP"

    # Every packet from a client to the target is an HTTP request, so it must be
    # going to port 80. Anything else means packets are being decoded at the
    # wrong offset, or -- as happened once here -- that a routing loop is
    # feeding mangled traffic back through the tunnel. Cheap to check, and it is
    # the assertion that catches the whole class of problem.
    stray=$(awk -F, -v target="$TARGET" \
        '$3 ~ /^172\.31\.66\./ && $5 == target && $6 != "80" { count++ } END { print count + 0 }' \
        "$TRANSPORT_CSV")
    if [ "$stray" -eq 0 ]; then
        log "ok: every client-to-target packet went to port 80"
    else
        log "FAIL: $stray client-to-target packet(s) recorded with a port other than 80"
        awk -F, -v target="$TARGET" \
            '$3 ~ /^172\.31\.66\./ && $5 == target && $6 != "80"' "$TRANSPORT_CSV" | head -5
        failures=$((failures + 1))
    fi
fi

log "--- the monitor's panel ---"
docker compose logs --no-log-prefix --tail 40 proxy || true

log "--- capture files ---"
wc -l "$CAPTURE_DIR"/*.csv 2>/dev/null || log "no capture files were written"

if [ "$failures" -eq 0 ]; then
    log "PASS"
    exit 0
fi

log "FAIL: $failures check(s) failed"
log "--- proxy log ---"
docker compose logs --tail 60 proxy || true
log "--- client1 log ---"
docker compose logs --tail 30 client1 || true
exit 1
