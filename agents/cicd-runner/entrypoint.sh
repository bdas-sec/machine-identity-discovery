#!/bin/bash
# Entrypoint script for CI/CD Runner Agent
# NHI Security Testbed - NDC Security 2026

set -e

echo "=========================================="
echo "NHI Testbed - CI/CD Runner Agent"
echo "=========================================="

WAZUH_MANAGER="${WAZUH_MANAGER:-172.42.0.254}"
WAZUH_REGISTRATION_SERVER="${WAZUH_REGISTRATION_SERVER:-$WAZUH_MANAGER}"
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME:-cicd-runner-$(hostname)}"
WAZUH_AGENT_GROUP="${WAZUH_AGENT_GROUP:-cicd,runner,ephemeral}"

echo "[*] Wazuh Manager: $WAZUH_MANAGER"
echo "[*] Agent Name: $WAZUH_AGENT_NAME"
echo "[*] Agent Groups: $WAZUH_AGENT_GROUP"

# Update ossec.conf
sed -i "s/WAZUH_MANAGER_IP/$WAZUH_MANAGER/g" /var/ossec/etc/ossec.conf
sed -i "s/WAZUH_AGENT_NAME/$WAZUH_AGENT_NAME/g" /var/ossec/etc/ossec.conf
sed -i "s/WAZUH_AGENT_GROUP/$WAZUH_AGENT_GROUP/g" /var/ossec/etc/ossec.conf

# Create marker file
touch /tmp/.cred_marker

# Wait for Wazuh manager
echo "[*] Waiting for Wazuh manager..."
MAX_RETRIES=30
RETRY_COUNT=0

while ! nc -z "$WAZUH_MANAGER" 1515 2>/dev/null; do
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "[!] Failed to connect to Wazuh manager"
        break
    fi
    sleep 5
done

# Register agent
if [ -f /var/ossec/etc/client.keys ] && [ -s /var/ossec/etc/client.keys ]; then
    echo "[*] Agent already registered"
else
    echo "[*] Registering agent..."
    /var/ossec/bin/agent-auth -m "$WAZUH_REGISTRATION_SERVER" -A "$WAZUH_AGENT_NAME" -G "$WAZUH_AGENT_GROUP" || true
fi

# Start auditd
if command -v auditd &>/dev/null; then
    service auditd start 2>/dev/null || auditd 2>/dev/null || true
    auditctl -w /runner/.credentials -p rwxa -k nhi_runner_creds 2>/dev/null || true
    auditctl -w /root/.npmrc -p rwxa -k nhi_npm_token 2>/dev/null || true
    auditctl -w /root/.docker -p rwxa -k nhi_docker_creds 2>/dev/null || true
fi

# Start Wazuh agent
echo "[*] Starting Wazuh agent..."
/var/ossec/bin/wazuh-control start

sleep 3
if /var/ossec/bin/wazuh-control status | grep -q "running"; then
    echo "[+] Wazuh agent started successfully"
fi

echo ""
echo "=========================================="
echo "CI/CD Runner Ready"
echo "=========================================="
echo "Runner Name: ${RUNNER_NAME:-github-runner-01}"
echo "Workspace: /runner/_work"
echo "Credentials: /runner/.credentials"
echo "=========================================="

exec "$@"
