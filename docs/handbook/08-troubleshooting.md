# Chapter 8: Troubleshooting

## Common Issues and Solutions

---

## Startup Issues

### Issue: Containers Won't Start

**Symptoms**:
- `docker compose up` fails
- Containers exit immediately

**Solutions**:

1. **Check Docker resources**:
```bash
docker info | grep -E "CPUs|Memory"
# Ensure at least 6GB RAM allocated to Docker
```

2. **Check vm.max_map_count**:
```bash
sysctl vm.max_map_count
# Must be >= 262144

# Fix:
sudo sysctl -w vm.max_map_count=262144
```

3. **Check port conflicts**:
```bash
sudo lsof -i :443
sudo lsof -i :9200
sudo lsof -i :55000

# Stop conflicting services or change ports in .env
```

4. **Check container logs**:
```bash
docker compose logs wazuh-indexer
docker compose logs wazuh-manager
```

---

### Issue: Certificate Generation Fails

**Symptoms**:
- `generate-certs.yml` errors
- SSL handshake failures

**Solutions**:

1. **Regenerate certificates**:
```bash
# Remove existing certs
rm -rf wazuh/certs/wazuh-certificates/

# Regenerate
docker compose -f wazuh/certs/generate-certs.yml run --rm generator
```

2. **Check certificate permissions**:
```bash
ls -la wazuh/certs/wazuh-certificates/
# Should be readable
```

3. **Verify certificate content**:
```bash
openssl x509 -in wazuh/certs/wazuh-certificates/wazuh.manager.pem -text -noout
```

---

## Agent Issues

### Issue: Agent Won't Connect

**Symptoms**:
- Agent shows "Disconnected" in dashboard
- Registration fails

**Solutions**:

1. **Check network connectivity**:
```bash
docker exec cloud-workload ping wazuh-manager
docker exec cloud-workload nc -zv wazuh-manager 1514
docker exec cloud-workload nc -zv wazuh-manager 1515
```

2. **Check registration password**:
```bash
# On manager
docker exec wazuh-manager cat /var/ossec/etc/authd.pass

# Should match AGENT_REGISTRATION_PASSWORD in .env
```

3. **Check agent logs**:
```bash
docker exec cloud-workload cat /var/ossec/logs/ossec.log | tail -50
```

4. **Re-register agent**:
```bash
docker exec cloud-workload /var/ossec/bin/agent-auth -m wazuh-manager
docker exec cloud-workload /var/ossec/bin/wazuh-control restart
```

---

### Issue: Agent Not Sending Events

**Symptoms**:
- Agent connected but no alerts
- Empty event log

**Solutions**:

1. **Verify ossec.conf log collection**:
```bash
docker exec cloud-workload cat /var/ossec/etc/ossec.conf | grep -A5 localfile
```

2. **Check if log files exist**:
```bash
docker exec cloud-workload ls -la /var/log/
```

3. **Generate test event**:
```bash
docker exec cloud-workload logger "TEST: This is a test event"
```

4. **Check agent buffer**:
```bash
docker exec cloud-workload cat /var/ossec/var/run/.agent_info
```

---

## Rule Issues

### Issue: Rules Not Triggering

**Symptoms**:
- Attack runs but no alert
- Rule exists but doesn't match

**Solutions**:

1. **Test rule manually**:
```bash
docker exec -it wazuh-manager /var/ossec/bin/wazuh-logtest

# Paste the log that should trigger the rule
# Example:
Jan  5 12:00:00 cloud-workload app: ACCESS 169.254.169.254
```

2. **Check rule syntax**:
```bash
docker exec wazuh-manager /var/ossec/bin/wazuh-control status
# Look for rule loading errors
```

3. **Verify rule is loaded**:
```bash
docker exec wazuh-manager ls -la /var/ossec/ruleset/rules/
docker exec wazuh-manager grep "100650" /var/ossec/ruleset/rules/*.xml
```

4. **Reload rules**:
```bash
docker exec wazuh-manager /var/ossec/bin/wazuh-control reload
```

---

### Issue: Too Many False Positives

**Symptoms**:
- Alerts for legitimate activity
- Alert fatigue

**Solutions**:

1. **Add exceptions**:
```xml
<rule id="100650" level="0">
  <if_sid>100650</if_sid>
  <srcip>172.41.0.10</srcip>
  <description>Silenced: Known good IMDS access</description>
</rule>
```

2. **Tune match patterns**:
```xml
<!-- More specific matching -->
<rule id="100651" level="12">
  <if_sid>100650</if_sid>
  <match>iam/security-credentials</match>
  <srcip>!172.41.0.10</srcip>  <!-- Exclude known good -->
</rule>
```

3. **Lower severity**:
```xml
<rule id="100600" level="4">  <!-- Was level 7 -->
```

---

## Performance Issues

### Issue: High Memory Usage

**Symptoms**:
- System slowdown
- OOM kills

**Solutions**:

1. **Check container memory**:
```bash
docker stats --no-stream
```

2. **Set memory limits in docker-compose.yml**:
```yaml
services:
  wazuh.indexer:
    deploy:
      resources:
        limits:
          memory: 2G
```

3. **Reduce indexer memory**:
```bash
# In indexer container
echo "-Xms512m" > /etc/opensearch/jvm.options.d/memory.options
echo "-Xmx512m" >> /etc/opensearch/jvm.options.d/memory.options
```

---

### Issue: Slow Dashboard

**Symptoms**:
- Dashboard takes long to load
- Queries timeout

**Solutions**:

1. **Check indexer health**:
```bash
curl -k -u admin:SecretPassword https://localhost:9200/_cluster/health?pretty
```

2. **Clear old indices**:
```bash
# List indices
curl -k -u admin:SecretPassword https://localhost:9200/_cat/indices

# Delete old indices
curl -k -u admin:SecretPassword -X DELETE https://localhost:9200/wazuh-alerts-4.x-2024.01.*
```

3. **Optimize queries**:
- Use time filters
- Limit result count
- Add specific field filters

---

## Scenario Runner Issues

### Issue: Scenario Fails

**Symptoms**:
- Runner reports failure
- Actions don't execute

**Solutions**:

1. **Check prerequisites**:
```bash
# Verify containers are running
docker compose ps

# Check network
docker exec cloud-workload curl http://mock-imds:1338/
```

2. **Run with verbose output**:
```bash
python src/scenario-runner/runner.py --run S2-01 --verbose
```

3. **Check action targets**:
```bash
# Verify endpoints are reachable
curl http://localhost:1338/latest/meta-data/
```

---

### Issue: Alert Validation Fails

**Symptoms**:
- Attack succeeds but alerts not found
- Validation timeout

**Solutions**:

1. **Increase wait time**:
```python
# In runner.py, increase sleep before validation
time.sleep(5)  # Was 2
```

2. **Check Wazuh API**:
```bash
curl -k -u wazuh-wui:MyS3cr3tP@ssw0rd https://localhost:55000/
```

3. **Skip validation for testing**:
```bash
python src/scenario-runner/runner.py --run S2-01 --no-validate
```

---

## Data Issues

### Issue: Lost Data After Restart

**Symptoms**:
- Alerts disappear
- Agents need re-registration

**Solutions**:

1. **Use persistent volumes**:
```yaml
# docker-compose.yml
volumes:
  wazuh_manager_data:
  wazuh_indexer_data:

services:
  wazuh.manager:
    volumes:
      - wazuh_manager_data:/var/ossec/data
```

2. **Don't use `--clean` flag**:
```bash
# Use this to preserve data:
./scripts/stop.sh

# NOT this:
./scripts/stop.sh --clean
```

---

## Getting Help

### Debug Information to Collect

```bash
# System info
uname -a
docker --version
docker compose version

# Container status
docker compose ps
docker compose logs > debug-logs.txt

# Agent status
docker exec wazuh-manager /var/ossec/bin/agent_control -l

# Rule check
docker exec wazuh-manager /var/ossec/bin/wazuh-logtest < test.log

# Network check
docker network ls
docker network inspect machine-identity-discovery_cloud_net
```

### Resources

- **Wazuh Documentation**: https://documentation.wazuh.com/
- **GitHub Issues**: https://github.com/RUDRA-Cybersecurity/machine-identity-discovery/issues
- **Wazuh Slack**: https://wazuh.com/community/join-us-on-slack/

### Reporting Issues

When reporting issues, include:
1. Steps to reproduce
2. Expected vs actual behavior
3. Debug information (above)
4. Docker and OS versions
