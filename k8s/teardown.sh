#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="nhi-testbed"

echo "[NHI] Tearing down Kind cluster '${CLUSTER_NAME}'..."

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    kind delete cluster --name "$CLUSTER_NAME"
    echo "[NHI] Cluster deleted"
else
    echo "[NHI] Cluster '${CLUSTER_NAME}' not found"
fi
