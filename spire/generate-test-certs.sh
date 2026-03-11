#!/bin/bash
# Generate dummy upstream CA certificates for SPIRE testbed
# These are self-signed test-only certificates — NOT for production use

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

generate_ca() {
    local dir="$1"
    local cn="$2"
    local org="$3"

    if [ -f "$dir/dummy_upstream_ca.key" ] && [ -f "$dir/dummy_upstream_ca.crt" ]; then
        echo "  [skip] $dir — certs already exist"
        return
    fi

    mkdir -p "$dir"
    openssl req -x509 -newkey rsa:2048 -keyout "$dir/dummy_upstream_ca.key" \
        -out "$dir/dummy_upstream_ca.crt" -days 365 -nodes \
        -subj "/C=US/O=$org/CN=$cn" 2>/dev/null

    echo "  [generated] $dir/dummy_upstream_ca.{key,crt} (CN=$cn)"
}

echo "Generating SPIRE test CA certificates..."
generate_ca "$SCRIPT_DIR/server" "example.org" "SPIRE-Testbed"
generate_ca "$SCRIPT_DIR/server-evil" "evil.org" "Evil-SPIRE-Testbed"
echo "Done."
