#!/bin/bash
# Entrypoint script for Vulnerable Application Agent
# NHI Security Testbed - NDC Security 2026

set -e

echo "=========================================="
echo "NHI Testbed - Vulnerable Application"
echo "=========================================="
echo "[!] WARNING: This container is INTENTIONALLY VULNERABLE"
echo "[!] DO NOT expose to untrusted networks"
echo ""

# Configuration from environment variables
WAZUH_MANAGER="${WAZUH_MANAGER:-172.41.0.254}"
WAZUH_REGISTRATION_SERVER="${WAZUH_REGISTRATION_SERVER:-$WAZUH_MANAGER}"
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME:-vulnerable-app-$(hostname)}"
WAZUH_AGENT_GROUP="${WAZUH_AGENT_GROUP:-cloud,vulnerable,demo}"

echo "[*] Wazuh Manager: $WAZUH_MANAGER"
echo "[*] Agent Name: $WAZUH_AGENT_NAME"
echo "[*] Agent Groups: $WAZUH_AGENT_GROUP"

# Update ossec.conf with actual values
echo "[*] Configuring Wazuh agent..."
sed -i "s/WAZUH_MANAGER_IP/$WAZUH_MANAGER/g" /var/ossec/etc/ossec.conf
sed -i "s/WAZUH_AGENT_NAME/$WAZUH_AGENT_NAME/g" /var/ossec/etc/ossec.conf
sed -i "s/WAZUH_AGENT_GROUP/$WAZUH_AGENT_GROUP/g" /var/ossec/etc/ossec.conf

# Fix permissions after config modification (required for wazuh user to read)
chown root:wazuh /var/ossec/etc/ossec.conf
chmod 640 /var/ossec/etc/ossec.conf

# Create log directory for Flask
mkdir -p /var/log/flask

# Wait for Wazuh manager to be available
echo "[*] Waiting for Wazuh manager at $WAZUH_MANAGER:1515..."
MAX_RETRIES=30
RETRY_COUNT=0

while ! nc -z "$WAZUH_MANAGER" 1515 2>/dev/null; do
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "[!] Failed to connect to Wazuh manager after $MAX_RETRIES attempts"
        break
    fi
    echo "[*] Waiting for manager... ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 5
done

# Register agent if not already registered
if [ -f /var/ossec/etc/client.keys ] && [ -s /var/ossec/etc/client.keys ]; then
    echo "[*] Agent already registered"
else
    echo "[*] Registering agent with manager..."
    /var/ossec/bin/agent-auth -m "$WAZUH_REGISTRATION_SERVER" -A "$WAZUH_AGENT_NAME" -G "$WAZUH_AGENT_GROUP" || {
        echo "[!] Registration failed, will retry on agent start"
    }
fi

# Start auditd if available
if command -v auditd &>/dev/null; then
    echo "[*] Starting auditd..."
    service auditd start 2>/dev/null || auditd 2>/dev/null || true

    # Add audit rules for web app monitoring
    auditctl -w /app/.env -p rwxa -k nhi_env_access 2>/dev/null || true
    auditctl -w /app -p w -k nhi_app_write 2>/dev/null || true
    auditctl -a always,exit -F arch=b64 -S open -F path=/proc -k nhi_proc_access 2>/dev/null || true
fi

# Start Wazuh agent
echo "[*] Starting Wazuh agent..."
/var/ossec/bin/wazuh-control start

# Verify agent is running
sleep 3
if /var/ossec/bin/wazuh-control status | grep -q "running"; then
    echo "[+] Wazuh agent started successfully"
else
    echo "[!] Warning: Wazuh agent may not have started properly"
fi

echo ""
echo "=========================================="
echo "Vulnerable Application Starting"
echo "=========================================="
echo "Endpoints available:"
echo "  http://localhost:8080/         - Index"
echo "  http://localhost:8080/.env     - VULNERABLE: .env exposure"
echo "  http://localhost:8080/debug    - VULNERABLE: env vars"
echo "  http://localhost:8080/config   - VULNERABLE: hardcoded secrets"
echo "=========================================="
echo ""

# Execute CMD (default: start Flask app)
exec "$@"
