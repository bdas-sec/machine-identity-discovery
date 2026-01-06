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
BACKUP_DIR="$PROJECT_DIR/.testbed-backup"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Detect container runtime
if command -v podman-compose &> /dev/null; then
    COMPOSE_CMD="podman-compose"
    RUNTIME="podman"
elif command -v podman &> /dev/null && command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
    RUNTIME="podman"
elif command -v docker &> /dev/null; then
    COMPOSE_CMD="docker compose"
    RUNTIME="docker"
else
    echo -e "${RED}ERROR: No container runtime found${NC}"
    exit 1
fi

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
    echo -e "${YELLOW}[1/7] Checking prerequisites...${NC}"

    # Check container runtime
    if [ "$RUNTIME" = "podman" ]; then
        echo "  [+] Podman: $(podman --version | cut -d' ' -f3)"
        echo "  [+] Compose: $COMPOSE_CMD"
    else
        echo "  [+] Docker: $(docker --version | cut -d' ' -f3)"
        echo "  [+] Docker Compose: $(docker compose version --short 2>/dev/null || echo 'v2')"
    fi

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
    echo -e "${YELLOW}[2/7] Setting up environment...${NC}"

    if [ ! -f "$PROJECT_DIR/.env" ]; then
        if [ -f "$PROJECT_DIR/.env.example" ]; then
            cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
            echo "  [+] Created .env from .env.example"
        else
            echo -e "${YELLOW}  [!] No .env.example found, using defaults${NC}"
        fi
    else
        echo "  [+] Using existing .env file"
    fi
}

# Generate certificates
generate_certs() {
    echo -e "${YELLOW}[3/7] Checking SSL certificates...${NC}"

    if [ ! -f "$PROJECT_DIR/wazuh/certs/root-ca.pem" ]; then
        echo "  [*] Generating SSL certificates..."
        cd "$PROJECT_DIR/wazuh/certs"
        $COMPOSE_CMD -f generate-certs.yml run --rm generator 2>/dev/null || {
            echo -e "${YELLOW}  [!] Certificate generator not available, using existing certs${NC}"
        }
        echo -e "${GREEN}  [+] Certificates generated${NC}"
    else
        echo "  [+] Certificates already exist"
    fi
}

# Build images
build_images() {
    echo -e "${YELLOW}[4/7] Building custom images...${NC}"

    cd "$PROJECT_DIR"

    if [ -n "$BUILD_FLAG" ]; then
        echo "  [*] Force rebuilding all images..."
        $COMPOSE_CMD $PROFILE build --no-cache 2>/dev/null || $COMPOSE_CMD build --no-cache
    else
        $COMPOSE_CMD $PROFILE build 2>/dev/null || $COMPOSE_CMD build
    fi

    echo -e "${GREEN}  [+] Images built${NC}"
}

# Start services
start_services() {
    echo -e "${YELLOW}[5/7] Starting services...${NC}"

    cd "$PROJECT_DIR"
    $COMPOSE_CMD $PROFILE up -d 2>/dev/null || $COMPOSE_CMD up -d

    echo -e "${GREEN}  [+] Services started${NC}"
}

# Wait for services
wait_for_services() {
    echo -e "${YELLOW}[6/7] Waiting for services to be healthy...${NC}"

    # Wait for Wazuh Indexer
    echo -n "  [*] Wazuh Indexer"
    RETRIES=0
    MAX_RETRIES=60
    until curl -sk -u admin:admin https://localhost:9200/_cluster/health 2>/dev/null | grep -qE '(green|yellow)'; do
        echo -n "."
        sleep 5
        RETRIES=$((RETRIES + 1))
        if [ $RETRIES -ge $MAX_RETRIES ]; then
            echo -e " ${RED}TIMEOUT${NC}"
            echo -e "${RED}  ERROR: Wazuh Indexer failed to start${NC}"
            $COMPOSE_CMD logs wazuh.indexer 2>/dev/null | tail -20
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
            $COMPOSE_CMD logs wazuh.manager 2>/dev/null | tail -20
            exit 1
        fi
    done
    echo -e " ${GREEN}OK${NC}"

    # Wait for Wazuh Dashboard (port 8443 for rootless podman)
    echo -n "  [*] Wazuh Dashboard"
    RETRIES=0
    MAX_RETRIES=30
    until curl -sk https://localhost:8443/status 2>/dev/null | grep -qE '(available|Unauthorized)'; do
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

# Restore agent groups from backup
restore_agent_groups() {
    echo -e "${YELLOW}[7/7] Restoring agent groups...${NC}"

    # Required groups for agents
    REQUIRED_GROUPS="cloud cicd runner ephemeral vulnerable demo ubuntu production"

    # Check if backup exists
    if [ -f "$BACKUP_DIR/agent_groups.txt" ]; then
        BACKUP_GROUPS=$(cat "$BACKUP_DIR/agent_groups.txt" 2>/dev/null | tr '\n' ' ')
        echo "  [*] Found backup: $BACKUP_GROUPS"
    fi

    # Get auth token
    TOKEN=$(curl -sk -u wazuh-wui:MyS3cr3tP@ssw0rd -X POST \
        "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null)

    if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
        echo -e "  ${YELLOW}[!] Could not authenticate to Wazuh API${NC}"
        return
    fi

    # Create required groups
    CREATED=0
    for group in $REQUIRED_GROUPS; do
        RESULT=$(curl -sk -H "Authorization: Bearer $TOKEN" \
            -X POST "https://localhost:55000/groups" \
            -H "Content-Type: application/json" \
            -d "{\"group_id\": \"$group\"}" 2>/dev/null)

        if echo "$RESULT" | grep -q "created"; then
            CREATED=$((CREATED + 1))
        fi
    done

    if [ $CREATED -gt 0 ]; then
        echo -e "  ${GREEN}[+] Created $CREATED agent groups${NC}"
    else
        echo -e "  ${GREEN}[+] All agent groups already exist${NC}"
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
    echo "  Wazuh Dashboard:  https://localhost:8443"
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
    echo "  View logs:     $COMPOSE_CMD logs -f"
    echo "  Stop testbed:  ./scripts/stop.sh"
    echo "  Run scenario:  ./scripts/demo/run-scenario.sh s2-01"
    echo ""
    echo -e "${YELLOW}Connected Agents:${NC}"
    $COMPOSE_CMD ps 2>/dev/null | grep -E "workload|runner|vulnerable" || true
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
    restore_agent_groups
    print_summary
}

main
