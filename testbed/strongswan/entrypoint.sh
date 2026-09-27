#!/bin/sh
# Give each peer a protected "inner" network on a dummy interface, start the
# responder's traffic servers, then run charon in the foreground.
set -e

ip link add inner type dummy 2>/dev/null || true
ip addr replace "$INNER_V4" dev inner
ip -6 addr replace "$INNER_V6" dev inner nodad
ip link set inner up

if [ "$ROLE" = "responder" ]; then
    python3 /usr/local/bin/traffic.py serve &
fi

exec /usr/lib/ipsec/charon
