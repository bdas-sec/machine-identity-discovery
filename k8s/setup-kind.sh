#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLUSTER_NAME="nhi-testbed"
NAMESPACE="nhi-testbed"
SPIRE_NAMESPACE="spire-system"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[NHI]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    for cmd in kind kubectl helm docker; do
        if ! command -v "$cmd" &>/dev/null; then
            err "$cmd is required but not installed"
            exit 1
        fi
    done
    log "All prerequisites met"
}

# Create Kind cluster
create_cluster() {
    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        warn "Cluster '${CLUSTER_NAME}' already exists"
        read -p "Delete and recreate? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            kind delete cluster --name "$CLUSTER_NAME"
        else
            log "Using existing cluster"
            return
        fi
    fi

    log "Creating Kind cluster '${CLUSTER_NAME}'..."

    # Ensure audit log directory exists on control-plane node after creation
    kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

    # Copy audit policy to control plane node
    docker exec "${CLUSTER_NAME}-control-plane" mkdir -p /etc/kubernetes /var/log/kubernetes
    docker cp "$SCRIPT_DIR/audit-policy.yaml" "${CLUSTER_NAME}-control-plane:/etc/kubernetes/audit-policy.yaml"

    log "Kind cluster created successfully"
    kubectl cluster-info --context "kind-${CLUSTER_NAME}"
}

# Build and load container images
load_images() {
    log "Building and loading container images into Kind..."

    local images=(
        "agents/cloud-workload:nhi-cloud-workload"
        "agents/vulnerable-app:nhi-vulnerable-app"
        "agents/cicd-runner:nhi-cicd-runner"
        "agents/k8s-node:nhi-k8s-node"
        "agents/ai-agent:nhi-ai-agent"
        "mock-services/imds:nhi-mock-imds"
        "mock-services/cicd-server:nhi-mock-cicd"
        "mock-services/gcp-metadata:nhi-mock-gcp"
        "mock-services/oauth-provider:nhi-mock-oauth"
        "mock-services/spire-simulator:nhi-spire-simulator"
    )

    for img in "${images[@]}"; do
        local context="${img%%:*}"
        local tag="${img##*:}"
        if [ -d "$PROJECT_ROOT/$context" ]; then
            log "  Building $tag..."
            docker build -t "$tag:latest" "$PROJECT_ROOT/$context" 2>/dev/null || warn "  Failed to build $tag (may not have Dockerfile)"
            kind load docker-image "$tag:latest" --name "$CLUSTER_NAME" 2>/dev/null || true
        fi
    done

    log "Images loaded"
}

# Install SPIRE via official Helm chart
install_spire() {
    log "Installing SPIRE via official Helm chart..."

    helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/ 2>/dev/null || true
    helm repo update

    kubectl create namespace "$SPIRE_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    helm upgrade --install spire spiffe/spire \
        --namespace "$SPIRE_NAMESPACE" \
        --set global.spire.trustDomain="example.org" \
        --set spire-server.logLevel="DEBUG" \
        --set spire-server.controllerManager.enabled=true \
        --set spire-agent.logLevel="DEBUG" \
        --wait --timeout 5m

    log "SPIRE installed in namespace $SPIRE_NAMESPACE"
}

# Deploy testbed via Helm
deploy_testbed() {
    log "Deploying NHI testbed via Helm..."

    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    helm upgrade --install nhi-testbed "$PROJECT_ROOT/helm/nhi-testbed" \
        --namespace "$NAMESPACE" \
        --set deployment.mode="kind" \
        --set spire.enabled=true \
        --set spire.externalServer=true \
        --set spire.serverNamespace="$SPIRE_NAMESPACE" \
        --wait --timeout 5m

    log "NHI testbed deployed in namespace $NAMESPACE"
}

# Print access info
print_info() {
    log ""
    log "========================================="
    log "  NHI Security Testbed (Kind Mode)"
    log "========================================="
    log ""
    log "  Wazuh Dashboard:  https://localhost:8443"
    log "  Dashboard UI:     http://localhost:3001"
    log "  Credentials:      admin / admin"
    log ""
    log "  kubectl context:  kind-${CLUSTER_NAME}"
    log "  Namespace:        ${NAMESPACE}"
    log "  SPIRE Namespace:  ${SPIRE_NAMESPACE}"
    log ""
    log "  Run scenarios:"
    log "    python .claude/skills/nhi-assistant/scripts/run_demo.py --all"
    log ""
    log "  Tear down:"
    log "    $SCRIPT_DIR/teardown.sh"
    log "========================================="
}

# Main
main() {
    log "NHI Security Testbed -- Kind Cluster Setup"
    log ""
    check_prerequisites
    create_cluster
    load_images
    install_spire
    deploy_testbed
    print_info
}

main "$@"
