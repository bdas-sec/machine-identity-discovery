#!/bin/bash
#
# Machine Identity Security Testbed - Stop Script
# NDC Security 2026
#
# Usage:
#   ./scripts/stop.sh           # Stop all services (preserves data)
#   ./scripts/stop.sh --clean   # Stop and remove volumes
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="$PROJECT_DIR/.testbed-backup"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Detect container runtime
if command -v podman-compose &> /dev/null; then
    COMPOSE_CMD="podman-compose"
elif command -v podman &> /dev/null && command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
elif command -v docker &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    echo -e "${RED}ERROR: No container runtime found${NC}"
    exit 1
fi

echo -e "${YELLOW}Stopping Machine Identity Security Testbed...${NC}"

cd "$PROJECT_DIR"

# Parse arguments
CLEAN_FLAG=""
if [[ "$1" == "--clean" ]]; then
    CLEAN_FLAG="-v"
    echo -e "${RED}  [!] Will also remove volumes (data will be lost)${NC}"
fi

# Backup agent groups before stopping (unless clean)
if [[ -z "$CLEAN_FLAG" ]]; then
    mkdir -p "$BACKUP_DIR"
    echo "[*] Backing up Wazuh configuration..."

    if curl -sk -u wazuh-wui:MyS3cr3tP@ssw0rd https://localhost:55000/ >/dev/null 2>&1; then
        # Get auth token
        TOKEN=$(curl -sk -u wazuh-wui:MyS3cr3tP@ssw0rd -X POST \
            "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null)

        if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
            # Backup groups
            curl -sk -H "Authorization: Bearer $TOKEN" \
                "https://localhost:55000/groups" 2>/dev/null | \
                python3 -c "import sys,json; data=json.load(sys.stdin); print('\n'.join([g['name'] for g in data.get('data',{}).get('affected_items',[]) if g['name'] != 'default']))" \
                > "$BACKUP_DIR/agent_groups.txt" 2>/dev/null || true

            GROUP_COUNT=$(wc -l < "$BACKUP_DIR/agent_groups.txt" 2>/dev/null || echo 0)
            echo -e "  ${GREEN}[+] Backed up $GROUP_COUNT agent groups${NC}"
        fi
    else
        echo -e "  ${YELLOW}[!] Wazuh API not available, skipping backup${NC}"
    fi
fi

# Stop all services
echo "[*] Stopping services..."
$COMPOSE_CMD down $CLEAN_FLAG 2>/dev/null || true

echo -e "${GREEN}[+] Testbed stopped${NC}"

if [[ -n "$CLEAN_FLAG" ]]; then
    echo -e "${YELLOW}[*] Volumes have been removed${NC}"
    rm -rf "$BACKUP_DIR" 2>/dev/null || true
    echo "    Run ./scripts/start.sh to recreate the environment"
else
    echo ""
    echo -e "${GREEN}Data preserved. Agent groups backed up to:${NC}"
    echo "  $BACKUP_DIR/agent_groups.txt"
    echo ""
    echo "Run ./scripts/start.sh to restart the testbed"
fi
