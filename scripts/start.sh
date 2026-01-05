#!/bin/bash
#
# Machine Identity Security Testbed - Startup Script
# NDC Security 2026 - "Who Gave the Agent Admin Rights?!"
#
# Usage:
#   ./scripts/start.sh              # Start core services
#   ./scripts/start.sh --all        # Start all services including K8s and AI
#   ./scripts/start.sh --k8s        # Include Kubernetes simulation
#   ./scripts/start.sh --ai         # Include AI agent
#   ./scripts/start.sh --build      # Force rebuild images
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "=========================================="
echo "  Machine Identity Security Testbed"
echo "  NDC Security 2026 Demo Environment"
echo "=========================================="
echo -e "${NC}"

# Parse arguments
PROFILE=""
BUILD_FLAG=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --all)
            PROFILE="--profile all"
            shift
            ;;
        --k8s)
            PROFILE="--profile k8s"
            shift
            ;;
        --ai)
            PROFILE="--profile ai"
            shift
            ;;
        --build)
            BUILD_FLAG="--build"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}[1/6] Checking prerequisites...${NC}"

    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}ERROR: Docker is not installed${NC}"
        echo "Install Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi
    echo "  [+] Docker: $(docker --version | cut -d' ' -f3)"

    # Check Docker Compose
    if ! docker compose version &> /dev/null; then
        echo -e "${RED}ERROR: Docker Compose is not available${NC}"
        echo "Docker Compose V2 is required"
        exit 1
    fi
    echo "  [+] Docker Compose: $(docker compose version --short)"

    # Check vm.max_map_count for OpenSearch
    MAX_MAP_COUNT=$(sysctl -n vm.max_map_count 2>/dev/null || echo "0")
    if [ "$MAX_MAP_COUNT" -lt 262144 ]; then
        echo -e "${YELLOW}  [!] WARNING: vm.max_map_count is $MAX_MAP_COUNT (recommended: 262144)${NC}"
        echo "      Run: sudo sysctl -w vm.max_map_count=262144"
        read -p "      Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        echo "  [+] vm.max_map_count: $MAX_MAP_COUNT"
    fi

    # Check available memory
    TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_MEM" -lt 6 ]; then
        echo -e "${YELLOW}  [!] WARNING: Low memory detected (${TOTAL_MEM}GB). Recommended: 8GB+${NC}"
    else
        echo "  [+] Available memory: ${TOTAL_MEM}GB"
    fi

    echo -e "${GREEN}  Prerequisites OK${NC}"
}

# Create .env if not exists
setup_env() {
    echo -e "${YELLOW}[2/6] Setting up environment...${NC}"

    if [ ! -f "$PROJECT_DIR/.env" ]; then
        if [ -f "$PROJECT_DIR/.env.example" ]; then
            cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
            echo "  [+] Created .env from .env.example"
        else
            echo -e "${RED}  ERROR: .env.example not found${NC}"
            exit 1
        fi
    else
        echo "  [+] Using existing .env file"
    fi
}

# Generate certificates
generate_certs() {
    echo -e "${YELLOW}[3/6] Checking SSL certificates...${NC}"

    if [ ! -f "$PROJECT_DIR/wazuh/certs/root-ca.pem" ]; then
        echo "  [*] Generating SSL certificates..."
        cd "$PROJECT_DIR/wazuh/certs"
        docker compose -f generate-certs.yml run --rm generator
        echo -e "${GREEN}  [+] Certificates generated${NC}"
    else
        echo "  [+] Certificates already exist"
    fi
}

# Build images
build_images() {
    echo -e "${YELLOW}[4/6] Building custom images...${NC}"

    cd "$PROJECT_DIR"

    if [ -n "$BUILD_FLAG" ]; then
        echo "  [*] Force rebuilding all images..."
        docker compose $PROFILE build --no-cache
    else
        docker compose $PROFILE build
    fi

    echo -e "${GREEN}  [+] Images built${NC}"
}

# Start services
start_services() {
    echo -e "${YELLOW}[5/6] Starting services...${NC}"

    cd "$PROJECT_DIR"
    docker compose $PROFILE up -d

    echo -e "${GREEN}  [+] Services started${NC}"
}

# Wait for services
wait_for_services() {
    echo -e "${YELLOW}[6/6] Waiting for services to be healthy...${NC}"

    # Wait for Wazuh Indexer
    echo -n "  [*] Wazuh Indexer"
    RETRIES=0
    MAX_RETRIES=60
    until curl -sk https://localhost:9200/_cluster/health 2>/dev/null | grep -qE '(green|yellow)'; do
        echo -n "."
        sleep 5
        RETRIES=$((RETRIES + 1))
        if [ $RETRIES -ge $MAX_RETRIES ]; then
            echo -e " ${RED}TIMEOUT${NC}"
            echo -e "${RED}  ERROR: Wazuh Indexer failed to start${NC}"
            docker compose logs wazuh.indexer | tail -20
            exit 1
        fi
    done
    echo -e " ${GREEN}OK${NC}"

    # Wait for Wazuh Manager
    echo -n "  [*] Wazuh Manager"
    RETRIES=0
    until curl -sk https://localhost:55000/ 2>/dev/null | grep -q "Wazuh"; do
        echo -n "."
        sleep 5
        RETRIES=$((RETRIES + 1))
        if [ $RETRIES -ge $MAX_RETRIES ]; then
            echo -e " ${RED}TIMEOUT${NC}"
            echo -e "${RED}  ERROR: Wazuh Manager failed to start${NC}"
            docker compose logs wazuh.manager | tail -20
            exit 1
        fi
    done
    echo -e " ${GREEN}OK${NC}"

    # Wait for Wazuh Dashboard
    echo -n "  [*] Wazuh Dashboard"
    RETRIES=0
    until curl -sk https://localhost:443/status 2>/dev/null | grep -q "available"; do
        echo -n "."
        sleep 5
        RETRIES=$((RETRIES + 1))
        if [ $RETRIES -ge $MAX_RETRIES ]; then
            echo -e " ${YELLOW}SLOW (may still be starting)${NC}"
            break
        fi
    done
    if [ $RETRIES -lt $MAX_RETRIES ]; then
        echo -e " ${GREEN}OK${NC}"
    fi

    # Wait for Mock IMDS
    echo -n "  [*] Mock IMDS"
    RETRIES=0
    MAX_RETRIES=20
    until curl -s http://localhost:1338/health 2>/dev/null | grep -q "healthy"; do
        echo -n "."
        sleep 2
        RETRIES=$((RETRIES + 1))
        if [ $RETRIES -ge $MAX_RETRIES ]; then
            echo -e " ${YELLOW}TIMEOUT${NC}"
            break
        fi
    done
    if [ $RETRIES -lt $MAX_RETRIES ]; then
        echo -e " ${GREEN}OK${NC}"
    fi
}

# Print summary
print_summary() {
    echo ""
    echo -e "${GREEN}=========================================="
    echo "  Testbed is Ready!"
    echo "==========================================${NC}"
    echo ""
    echo -e "${BLUE}Access Points:${NC}"
    echo "  Wazuh Dashboard:  https://localhost:443"
    echo "  Wazuh API:        https://localhost:55000"
    echo "  Vault UI:         http://localhost:8200"
    echo "  Mock IMDS:        http://localhost:1338"
    echo "  Mock CI/CD:       http://localhost:8080"
    echo "  Vulnerable App:   http://localhost:8888"
    echo ""
    echo -e "${BLUE}Default Credentials:${NC}"
    echo "  Dashboard:  admin / SecretPassword"
    echo "  API:        wazuh-wui / MyS3cr3tP@ssw0rd"
    echo "  Vault:      root-token-for-demo"
    echo ""
    echo -e "${BLUE}Quick Commands:${NC}"
    echo "  View logs:     docker compose logs -f"
    echo "  Stop testbed:  ./scripts/stop.sh"
    echo "  Run scenario:  ./scripts/demo/run-scenario.sh s2-01"
    echo ""
    echo -e "${YELLOW}Connected Agents:${NC}"
    docker compose ps --format "table {{.Name}}\t{{.Status}}" | grep -E "agent|workload|runner|node"
    echo ""
}

# Main
main() {
    cd "$PROJECT_DIR"

    check_prerequisites
    setup_env
    generate_certs
    build_images
    start_services
    wait_for_services
    print_summary
}

main
