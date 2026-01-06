# NHI Testbed Troubleshooting Guide

This guide documents issues encountered during testbed setup and their solutions.

## Table of Contents

1. [Agent Enrollment Issues](#agent-enrollment-issues)
2. [Container Issues](#container-issues)
3. [Dashboard Issues](#dashboard-issues)
4. [Test Failures](#test-failures)
5. [Network Issues](#network-issues)

---

## Agent Enrollment Issues

### "Invalid group" Error

**Symptoms:**
```
wazuh-authd: INFO: Received request for a new agent (cloud-workload-001) from: 172.41.0.10
wazuh-authd: ERROR: Invalid group: cloud
```

**Cause:** Agent groups must exist on the manager before agents can enroll with those groups.

**Solution:**
```bash
# Get auth token
TOKEN=$(curl -sk -u wazuh-wui:MyS3cr3tP@ssw0rd -X POST \
  "https://localhost:55000/security/user/authenticate?raw=true")

# Create all required groups
for group in cloud cicd runner ephemeral vulnerable demo ubuntu production; do
  curl -sk -H "Authorization: Bearer $TOKEN" \
    -X POST "https://localhost:55000/groups" \
    -H "Content-Type: application/json" \
    -d "{\"group_id\": \"$group\"}"
done

# Restart agent containers
podman restart cloud-workload vulnerable-app cicd-runner
```

### ossec.conf XML Read Error (Line 0)

**Symptoms:**
```
wazuh-control: ERROR: Error reading local configuration (ossec.conf) (line 0).
```

**Cause:** The `ossec.conf` file has wrong permissions. After `sed` modifies the file in the entrypoint, it may become owned by root:root with 600 permissions, but the wazuh user needs to read it.

**Solution:**
Add to agent entrypoint.sh after sed commands:
```bash
# Fix permissions after config modification
chown root:wazuh /var/ossec/etc/ossec.conf
chmod 640 /var/ossec/etc/ossec.conf
```

**Files to update:**
- `agents/cloud-workload/entrypoint.sh`
- `agents/vulnerable-app/entrypoint.sh`
- `agents/cicd-runner/entrypoint.sh`

### Duplicate Agent Name Error

**Symptoms:**
```
wazuh-authd: ERROR: Duplicate agent name (cloud-workload-001)
```

**Cause:** Agent was previously registered but container was recreated.

**Solution:**
```bash
# Get token
TOKEN=$(curl -sk -u wazuh-wui:MyS3cr3tP@ssw0rd -X POST \
  "https://localhost:55000/security/user/authenticate?raw=true")

# List agents to find IDs
curl -sk -H "Authorization: Bearer $TOKEN" "https://localhost:55000/agents"

# Delete old agent (e.g., ID 001)
curl -sk -H "Authorization: Bearer $TOKEN" \
  -X DELETE "https://localhost:55000/agents?agents_list=001&status=all&older_than=0s"

# Restart container
podman restart cloud-workload
```

---

## Container Issues

### Port 443 Permission Denied

**Symptoms:**
```
Error: rootlessport cannot expose privileged port 443
```

**Cause:** Rootless Podman cannot bind to ports below 1024.

**Solution:**
Use port 8443 instead of 443 in docker-compose.yml:
```yaml
wazuh.dashboard:
  ports:
    - "8443:5601"  # Changed from 443:5601
```

### Container Name Format Issues

**Symptoms:** Tests fail with "container not found" errors.

**Cause:** Podman uses hyphens in container names, not dots.

**Solution:**
In tests, use `wazuh-manager` not `wazuh.manager`:
```python
# Correct
container_name = "wazuh-manager"

# Incorrect
container_name = "wazuh.manager"
```

### Image Build Failures

**Symptoms:** Build fails with package installation errors.

**Solution:**
```bash
# Clean up and rebuild
podman system prune -f
podman-compose build --no-cache

# Or use the start script
./scripts/start.sh --build
```

### Container Won't Stop (SIGTERM Timeout)

**Symptoms:**
```
StopSignal SIGTERM failed to stop container in 10 seconds, resorting to SIGKILL
```

**Cause:** Container process ignoring SIGTERM.

**Solution:** This is usually harmless. The container will be killed via SIGKILL.

---

## Dashboard Issues

### Dashboard Connecting to localhost:9200

**Symptoms:**
- Dashboard unhealthy
- Logs show connection refused to localhost:9200

**Cause:** Dashboard default config tries to connect to localhost instead of the indexer container hostname.

**Solution:**
Create explicit config file `wazuh/dashboard-config/opensearch_dashboards.yml`:
```yaml
server.host: "0.0.0.0"
server.port: 5601
server.ssl.enabled: true
server.ssl.certificate: /etc/wazuh-dashboard/certs/dashboard.pem
server.ssl.key: /etc/wazuh-dashboard/certs/dashboard-key.pem

opensearch.hosts: ["https://wazuh.indexer:9200"]
opensearch.ssl.verificationMode: certificate
opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
opensearch.username: "kibanaserver"
opensearch.password: "kibanaserver"
opensearch.requestTimeout: 30000
```

Mount in docker-compose.yml:
```yaml
wazuh.dashboard:
  volumes:
    - ./wazuh/dashboard-config/opensearch_dashboards.yml:/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml:ro
```

### Invalid Config Key Error

**Symptoms:**
```
FATAL Error: Unknown configuration key 'wazuh.monitoring.enabled'
```

**Solution:** Remove any `wazuh.*` keys from opensearch_dashboards.yml - they're not valid for the base OpenSearch Dashboards config.

### Dashboard Slow to Start

**Symptoms:** Dashboard takes 2-3 minutes to become healthy.

**Cause:** Normal behavior - dashboard needs to initialize plugins and connect to indexer.

**Solution:** Wait longer, or check logs:
```bash
podman-compose logs -f wazuh-dashboard
```

---

## Test Failures

### Agent Name Mismatch

**Symptoms:**
```
AssertionError: Expected agent 'cloud-workload' not found
```

**Cause:** Agents register with `-001` suffix (e.g., `cloud-workload-001`).

**Solution:**
Update test expectations:
```python
EXPECTED_AGENTS = [
    "cloud-workload-001",
    "vulnerable-app-001",
    "cicd-runner-001",
]
```

### Docker vs Podman Detection

**Symptoms:** Tests fail with "docker: command not found".

**Solution:**
Use runtime auto-detection in test helpers:
```python
def _get_container_runtime() -> str:
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return "docker"

CONTAINER_RUNTIME = _get_container_runtime()
```

### Container Connectivity Test Failures

**Symptoms:** `can_reach()` tests fail even though services are running.

**Cause:** Different containers have different tools available (nc, curl, or neither).

**Solution:**
Try multiple methods:
```python
def can_reach(container: str, host: str, port: int) -> bool:
    # Try nc first
    result = run_in_container(container, f"nc -z {host} {port}")
    if result.returncode == 0:
        return True

    # Try curl
    result = run_in_container(container, f"curl -s --connect-timeout 2 {host}:{port}")
    if result.returncode == 0:
        return True

    # Try bash /dev/tcp
    result = run_in_container(container, f"bash -c 'echo > /dev/tcp/{host}/{port}'")
    return result.returncode == 0
```

---

## Network Issues

### Services Can't Communicate

**Symptoms:** Containers can't reach each other by hostname.

**Solution:**
Ensure containers are on the same network:
```yaml
networks:
  wazuh-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.41.0.0/24
```

### IMDS Not Accessible

**Symptoms:** Cloud workload can't reach mock-imds at 169.254.169.254.

**Cause:** The mock IMDS uses internal IP, not the AWS link-local address.

**Solution:**
Access via container hostname:
```bash
curl http://mock-imds:1338/latest/meta-data/
```

Or use the internal IP:
```bash
curl http://172.41.0.100:1338/latest/meta-data/
```

---

## Quick Diagnostic Commands

```bash
# Check all container status
podman-compose ps

# Check container logs
podman-compose logs wazuh-manager
podman-compose logs cloud-workload

# Check indexer health
curl -sk -u admin:admin https://localhost:9200/_cluster/health

# Check API health
curl -sk https://localhost:55000/

# List agents
TOKEN=$(curl -sk -u wazuh-wui:MyS3cr3tP@ssw0rd -X POST \
  "https://localhost:55000/security/user/authenticate?raw=true")
curl -sk -H "Authorization: Bearer $TOKEN" "https://localhost:55000/agents"

# Run smoke tests
.venv/bin/python -m pytest tests/smoke/ -v

# Check agent logs inside container
podman exec cloud-workload cat /var/ossec/logs/ossec.log | tail -50
```
