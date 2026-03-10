#!/bin/bash
# SPIRE Agent entrypoint — auto-attest with join token from server
# For testbed use only (production uses k8s_sat or x509pop attestors)

set -e

SPIRE_SERVER="${SPIRE_SERVER:-spire-server}"
SPIRE_SERVER_PORT="${SPIRE_SERVER_PORT:-8081}"
MAX_RETRIES=30
RETRY_COUNT=0

echo "[*] Waiting for SPIRE server at ${SPIRE_SERVER}:${SPIRE_SERVER_PORT}..."

# Wait for server to be reachable
while ! nc -z "$SPIRE_SERVER" "$SPIRE_SERVER_PORT" 2>/dev/null; do
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ "$RETRY_COUNT" -ge "$MAX_RETRIES" ]; then
        echo "[!] Failed to connect to SPIRE server after $MAX_RETRIES attempts"
        exit 1
    fi
    sleep 2
done

echo "[+] SPIRE server is reachable"

# Check if agent is already attested (has SVID bundle)
if [ -f /opt/spire/data/agent/agent_svid.der ]; then
    echo "[*] Agent already attested, starting directly..."
    exec /opt/spire/bin/spire-agent run -config /opt/spire/conf/agent/agent.conf
fi

# Generate join token from server (requires server API access)
# In testbed, the server socket is accessible via the network
echo "[*] Requesting join token from SPIRE server..."

# Use the join token passed via environment variable, or fall back to a pre-generated one
if [ -n "$SPIRE_JOIN_TOKEN" ]; then
    TOKEN="$SPIRE_JOIN_TOKEN"
    echo "[+] Using provided join token"
else
    echo "[!] No SPIRE_JOIN_TOKEN provided. Set it via environment variable."
    echo "[!] Generate one with: docker exec spire-server /opt/spire/bin/spire-server token generate -spiffeID spiffe://example.org/spire-agent -socketPath /tmp/spire-server/private/api.sock"
    exit 1
fi

echo "[*] Starting SPIRE agent with join token attestation..."
exec /opt/spire/bin/spire-agent run -config /opt/spire/conf/agent/agent.conf -joinToken "$TOKEN"
