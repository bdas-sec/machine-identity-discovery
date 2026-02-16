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
    echo -e "${YELLOW}[1/9] Checking prerequisites...${NC}"

    # Check container runtime
    if [ "$RUNTIME" = "podman" ]; then
        echo "  [+] Podman: $(podman --version | cut -d' ' -f3)"
        echo "  [+] Compose: $COMPOSE_CMD"
    else
        echo "  [+] Docker: $(docker --version | cut -d' ' -f3)"
        echo "  [+] Docker Compose: $(docker compose version --short 2>/dev/null || echo 'v2')"
    fi

    # Check vm.max_map_count for OpenSearch
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS: check inside Colima/Docker VM instead of host
        VM_MAP_COUNT=$(colima ssh -- sysctl -n vm.max_map_count 2>/dev/null || docker run --rm --privileged alpine sysctl -n vm.max_map_count 2>/dev/null || echo "0")
        if [ "$VM_MAP_COUNT" -ge 262144 ]; then
            echo "  [+] vm.max_map_count: $VM_MAP_COUNT (inside VM)"
        else
            echo -e "${YELLOW}  [!] WARNING: vm.max_map_count is $VM_MAP_COUNT in Docker VM${NC}"
            echo "      Run: colima ssh -- sudo sysctl -w vm.max_map_count=262144"
            read -p "      Continue anyway? (y/N) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    else
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
    fi

    # Check available memory
    if [[ "$(uname)" == "Darwin" ]]; then
        TOTAL_MEM=$(( $(sysctl -n hw.memsize 2>/dev/null) / 1073741824 ))
    else
        TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
    fi
    if [ "$TOTAL_MEM" -lt 6 ]; then
        echo -e "${YELLOW}  [!] WARNING: Low memory detected (${TOTAL_MEM}GB). Recommended: 8GB+${NC}"
    else
        echo "  [+] Available memory: ${TOTAL_MEM}GB"
    fi

    echo -e "${GREEN}  Prerequisites OK${NC}"
}

# Create .env if not exists
setup_env() {
    echo -e "${YELLOW}[2/9] Setting up environment...${NC}"

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

# Fix certificate permissions (needed for Podman rootless)
fix_cert_permissions() {
    echo -e "${YELLOW}[3/9] Fixing certificate permissions...${NC}"

    CERTS_DIR="$PROJECT_DIR/wazuh/certs"

    # Check if certs directory has restricted permissions (from previous podman runs)
    if [ ! -r "$CERTS_DIR" ] 2>/dev/null; then
        echo "  [*] Fixing certificate directory permissions..."
        if [ "$RUNTIME" = "podman" ]; then
            podman unshare chown -R 0:0 "$CERTS_DIR" 2>/dev/null || true
        fi
        chmod -R 755 "$CERTS_DIR" 2>/dev/null || true
    fi

    # Ensure all cert files are readable
    if [ -d "$CERTS_DIR" ]; then
        find "$CERTS_DIR" -name "*.pem" -exec chmod 644 {} \; 2>/dev/null || true
        find "$CERTS_DIR" -name "*.key" -exec chmod 644 {} \; 2>/dev/null || true
    fi

    echo -e "${GREEN}  [+] Certificate permissions OK${NC}"
}

# Generate certificates
generate_certs() {
    echo -e "${YELLOW}[4/9] Checking SSL certificates...${NC}"

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
    echo -e "${YELLOW}[5/9] Building custom images...${NC}"

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
    echo -e "${YELLOW}[6/9] Starting services...${NC}"

    cd "$PROJECT_DIR"
    $COMPOSE_CMD $PROFILE up -d 2>/dev/null || $COMPOSE_CMD up -d

    echo -e "${GREEN}  [+] Services started${NC}"
}

# Initialize Wazuh Indexer security (required on first run)
initialize_indexer_security() {
    echo -e "${YELLOW}[7/9] Initializing indexer security...${NC}"

    # Wait for indexer to be ready (but not necessarily healthy - it needs security init first)
    echo -n "  [*] Waiting for indexer to start"
    RETRIES=0
    MAX_RETRIES=30
    until $RUNTIME exec wazuh-indexer curl -sk https://localhost:9200/ 2>/dev/null | grep -q "OpenSearch"; do
        echo -n "."
        sleep 3
        RETRIES=$((RETRIES + 1))
        if [ $RETRIES -ge $MAX_RETRIES ]; then
            echo -e " ${YELLOW}TIMEOUT${NC}"
            echo -e "  ${YELLOW}[!] Indexer may need manual intervention${NC}"
            return
        fi
    done
    echo -e " ${GREEN}OK${NC}"

    # Check if security is already initialized
    if curl -sk -u admin:admin https://localhost:9200/_cluster/health 2>/dev/null | grep -qE '(green|yellow)'; then
        echo -e "  ${GREEN}[+] Security already initialized${NC}"
        return
    fi

    # Initialize security
    echo "  [*] Running security initialization..."
    $RUNTIME exec wazuh-indexer bash -c "JAVA_HOME=/usr/share/wazuh-indexer/jdk /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
        -cd /usr/share/wazuh-indexer/opensearch-security/ \
        -icl -nhnv \
        -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
        -cert /usr/share/wazuh-indexer/certs/admin.pem \
        -key /usr/share/wazuh-indexer/certs/admin-key.pem \
        -h localhost" 2>/dev/null

    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}[+] Security initialized successfully${NC}"
    else
        echo -e "  ${YELLOW}[!] Security initialization may have issues${NC}"
    fi
}

# Create agent groups (must be done before agents try to enroll)
create_agent_groups() {
    echo "  [*] Creating agent groups..."

    # Required groups for agents
    REQUIRED_GROUPS="cloud cicd runner ephemeral vulnerable demo ubuntu production"

    # Get auth token
    TOKEN=$(curl -sk -u wazuh-wui:MyS3cr3tP@ssw0rd -X POST \
        "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null)

    if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
        echo -e "  ${YELLOW}[!] Could not authenticate to Wazuh API${NC}"
        return 1
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

    return 0
}

# Restart agent containers to re-enroll with groups
restart_agents() {
    echo "  [*] Restarting agents to re-enroll..."

    # Restart all agent containers
    $RUNTIME restart cloud-workload vulnerable-app cicd-runner 2>/dev/null || true

    # Wait a moment for agents to start enrolling
    sleep 5

    echo -e "  ${GREEN}[+] Agents restarted${NC}"
}

# Wait for services to be healthy
wait_for_services() {
    echo -e "${YELLOW}[8/9] Waiting for services to be healthy...${NC}"

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

    # Wait for Wazuh Manager API
    echo -n "  [*] Wazuh Manager"
    RETRIES=0
    MAX_RETRIES=30  # Reduce timeout for manager check
    until curl -sk https://localhost:55000/ 2>/dev/null | grep -qE '(Wazuh|Unauthorized|title)'; do
        echo -n "."
        sleep 3
        RETRIES=$((RETRIES + 1))
        if [ $RETRIES -ge $MAX_RETRIES ]; then
            echo -e " ${RED}TIMEOUT${NC}"
            echo -e "${RED}  ERROR: Wazuh Manager API failed to start${NC}"
            $COMPOSE_CMD logs wazuh.manager 2>/dev/null | tail -20
            exit 1
        fi
    done
    echo -e " ${GREEN}OK${NC}"

    # CRITICAL: Create agent groups IMMEDIATELY after manager is available
    # Agents are already trying to enroll at this point, so groups must exist
    create_agent_groups

    # Restart agents to re-enroll now that groups exist
    restart_agents

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

    # Wait for Mock OAuth Provider
    echo -n "  [*] Mock OAuth"
    RETRIES=0
    MAX_RETRIES=20
    until curl -s http://localhost:8090/health 2>/dev/null | grep -q "healthy"; do
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

    # Wait for Mock GCP Metadata
    echo -n "  [*] Mock GCP Metadata"
    RETRIES=0
    MAX_RETRIES=20
    until curl -s -H "Metadata-Flavor: Google" http://localhost:1339/health 2>/dev/null | grep -q "healthy"; do
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

    # Wait for agents to connect
    echo -n "  [*] Waiting for agents to connect"
    RETRIES=0
    MAX_RETRIES=30
    until $RUNTIME exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -q "Active"; do
        echo -n "."
        sleep 3
        RETRIES=$((RETRIES + 1))
        if [ $RETRIES -ge $MAX_RETRIES ]; then
            echo -e " ${YELLOW}TIMEOUT${NC}"
            echo -e "  ${YELLOW}[!] Agents may need manual restart${NC}"
            break
        fi
    done
    if [ $RETRIES -lt $MAX_RETRIES ]; then
        echo -e " ${GREEN}OK${NC}"
        AGENT_COUNT=$($RUNTIME exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null | grep -c "Active" || echo "0")
        echo -e "  ${GREEN}[+] $AGENT_COUNT agents connected${NC}"
    fi
}

# Install NHI detection rules and decoders
install_nhi_rules() {
    echo -e "${YELLOW}[9/9] Installing NHI detection rules...${NC}"

    # Check if rules are staged
    if ! $RUNTIME exec wazuh-manager test -f /tmp/nhi-rules/nhi-detection-rules.xml 2>/dev/null; then
        echo -e "  ${YELLOW}[!] NHI rules not staged, skipping${NC}"
        return
    fi

    # Copy rules and decoders to Wazuh
    echo "  [*] Copying rules and decoders..."
    $RUNTIME exec wazuh-manager bash -c "cp /tmp/nhi-rules/nhi-detection-rules.xml /var/ossec/etc/rules/ 2>/dev/null && \
        cp /tmp/nhi-rules/nhi-decoders.xml /var/ossec/etc/decoders/ 2>/dev/null && \
        chown wazuh:wazuh /var/ossec/etc/rules/nhi-detection-rules.xml 2>/dev/null && \
        chown wazuh:wazuh /var/ossec/etc/decoders/nhi-decoders.xml 2>/dev/null"

    # Install local decoder for NHI_ALERT syslog entries
    echo "  [*] Installing NHI_ALERT decoder and demo rules..."
    $RUNTIME exec wazuh-manager bash -c 'cat > /var/ossec/etc/decoders/local_decoder.xml << '\''XMLEOF'\''
<!-- Local Decoders -->
<!-- Copyright (C) 2015, Wazuh Inc. -->

<!-- NHI Testbed Decoder - matches Flask app security log entries -->
<decoder name="nhi_alert">
    <program_name>NHI_ALERT</program_name>
</decoder>

<!-- NHI SSRF URL extractor -->
<decoder name="nhi_alert_url">
    <parent>nhi_alert</parent>
    <regex type="pcre2">SSRF request to (.+?)(?:\s+from|$)</regex>
    <order>url</order>
</decoder>
XMLEOF'

    # Install local rules for demo kill chain alerts
    $RUNTIME exec wazuh-manager bash -c 'cat > /var/ossec/etc/rules/local_rules.xml << '\''XMLEOF'\''
<!-- Local rules -->
<!-- Copyright (C) 2015, Wazuh Inc. -->

<!-- NHI Testbed Demo Rules - Kill Chain Alerts -->
<group name="nhi,demo,">

  <rule id="100010" level="3">
    <program_name>NHI_ALERT</program_name>
    <description>NHI Testbed log entry</description>
  </rule>

  <rule id="100011" level="10">
    <if_sid>100010</if_sid>
    <match type="pcre2">SSRF.*mock-imds</match>
    <description>NHI: SSRF request targeting cloud metadata service (IMDS)</description>
    <mitre><id>T1552.005</id></mitre>
    <group>nhi_imds,attack,</group>
  </rule>

  <rule id="100012" level="12">
    <if_sid>100011</if_sid>
    <match>security-credentials</match>
    <description>NHI: IMDS IAM credential theft via SSRF - CRITICAL</description>
    <mitre><id>T1552.005</id><id>T1078.004</id></mitre>
    <group>nhi_imds_cred,attack,</group>
  </rule>

  <rule id="100013" level="12">
    <if_sid>100011</if_sid>
    <match>iam/info</match>
    <description>NHI: IMDS IAM role privilege discovery via SSRF</description>
    <mitre><id>T1078.004</id></mitre>
    <group>nhi_imds_priv,attack,</group>
  </rule>

  <rule id="100014" level="8">
    <if_sid>100010</if_sid>
    <match>ENV_FILE</match>
    <description>NHI: Sensitive environment file accessed - credential exposure</description>
    <mitre><id>T1552.001</id></mitre>
    <group>nhi_env_access,attack,</group>
  </rule>

  <rule id="100015" level="8">
    <if_sid>100010</if_sid>
    <match>DEBUG_ENDPOINT</match>
    <description>NHI: Debug endpoint accessed - environment variable leak</description>
    <mitre><id>T1082</id></mitre>
    <group>nhi_debug_access,attack,</group>
  </rule>

  <rule id="100016" level="10">
    <if_sid>100010</if_sid>
    <match>CICD_SECRET</match>
    <description>NHI: CI/CD pipeline secrets accessed - lateral movement</description>
    <mitre><id>T1528</id></mitre>
    <group>nhi_cicd,attack,</group>
  </rule>

</group>
XMLEOF'

    # Fix Filebeat SSL verification for self-signed certs
    echo "  [*] Fixing Filebeat TLS configuration..."
    $RUNTIME exec wazuh-manager bash -c "sed -i \"s/ssl.verification_mode: 'full'/ssl.verification_mode: 'none'/\" /etc/filebeat/filebeat.yml 2>/dev/null" || true

    # Reload Wazuh to pick up new rules
    echo "  [*] Reloading Wazuh rules..."
    $RUNTIME exec wazuh-manager /var/ossec/bin/wazuh-control reload 2>/dev/null || true

    # Restart Filebeat to apply TLS fix
    $RUNTIME exec wazuh-manager bash -c "pkill filebeat; sleep 2; filebeat -c /etc/filebeat/filebeat.yml &" 2>/dev/null || true

    # Verify rules loaded
    RULE_COUNT=$($RUNTIME exec wazuh-manager grep -c "rule id=\"100" /var/ossec/etc/rules/nhi-detection-rules.xml 2>/dev/null || echo "0")
    if [ "$RULE_COUNT" -gt 0 ]; then
        echo -e "  ${GREEN}[+] Loaded $RULE_COUNT NHI detection rules${NC}"
    else
        echo -e "  ${YELLOW}[!] Warning: Could not verify rules loaded${NC}"
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
    echo "  Mock GCP Meta:    http://localhost:1339"
    echo "  Mock CI/CD:       http://localhost:8080"
    echo "  Mock OAuth:       http://localhost:8090"
    echo "  Vulnerable App:   http://localhost:8888"
    echo ""
    echo -e "${BLUE}Monitoring:${NC}"
    echo "  Grafana:          http://localhost:3000  (admin / admin)"
    echo "  Prometheus:       http://localhost:9090"
    echo "  Metrics Exporter: http://localhost:9091/metrics"
    echo ""
    echo -e "${BLUE}Default Credentials:${NC}"
    echo "  Dashboard:  admin / admin"
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
    fix_cert_permissions
    generate_certs
    build_images
    start_services
    initialize_indexer_security
    wait_for_services  # This now includes agent group creation and agent restart
    install_nhi_rules
    print_summary
}

main
