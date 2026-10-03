#!/bin/sh
# Build the agent's trust store, then hand over to the requested command.
#
# The agent trusts two authorities: the lab CA that signs the fake internet's
# servers, and the firewall's interception CA. The second one only exists once
# the firewall has started, so wait for it rather than racing.
set -e

PKI_DIR="${PKI_DIR:-/pki}"
BUNDLE="${LAB_CA_BUNDLE:-/run/trust/bundle.pem}"
mkdir -p "$(dirname "$BUNDLE")"

wait_for() {
    file="$1"
    waited=0
    while [ ! -f "$file" ]; do
        if [ "$waited" -ge 60 ]; then
            echo "agent: giving up waiting for $file" >&2
            return 1
        fi
        sleep 1
        waited=$((waited + 1))
    done
    return 0
}

: > "$BUNDLE"
if wait_for "$PKI_DIR/lab-ca.pem"; then
    cat "$PKI_DIR/lab-ca.pem" >> "$BUNDLE"
fi
if wait_for "$PKI_DIR/mitm-ca.pem"; then
    cat "$PKI_DIR/mitm-ca.pem" >> "$BUNDLE"
fi

# Also make the bundle the default for anything that reads the standard
# variables, so a tool added later inherits the same trust.
export SSL_CERT_FILE="$BUNDLE"
export REQUESTS_CA_BUNDLE="$BUNDLE"

exec "$@"
