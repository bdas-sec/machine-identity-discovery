#!/bin/bash
#
# Machine Identity Security Testbed - Stop Script
# NDC Security 2026
#
# Usage:
#   ./scripts/stop.sh           # Stop all services
#   ./scripts/stop.sh --clean   # Stop and remove volumes
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Stopping Machine Identity Security Testbed...${NC}"

cd "$PROJECT_DIR"

# Parse arguments
CLEAN_FLAG=""
if [[ "$1" == "--clean" ]]; then
    CLEAN_FLAG="-v"
    echo -e "${RED}  [!] Will also remove volumes (data will be lost)${NC}"
fi

# Stop all services (including all profiles)
echo "[*] Stopping services..."
docker compose --profile all down $CLEAN_FLAG

echo -e "${GREEN}[+] Testbed stopped${NC}"

if [[ -n "$CLEAN_FLAG" ]]; then
    echo -e "${YELLOW}[*] Volumes have been removed${NC}"
    echo "    Run ./scripts/start.sh to recreate the environment"
fi
