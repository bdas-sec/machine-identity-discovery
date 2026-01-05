# Chapter 7: Extending the Testbed

## Overview

This chapter covers how to extend the NHI Security Testbed with custom scenarios, rules, and agent types.

---

## Adding New Scenarios

### Scenario JSON Structure

```json
{
  "id": "S6-01",
  "name": "Custom Scenario Name",
  "category": "Custom Category",
  "version": "1.0",
  "description": "Brief description of the attack",
  "difficulty": "Easy|Medium|Hard",
  "real_world_relevance": "Real breach or common attack pattern",

  "mitre_attack": {
    "tactics": ["Tactic1", "Tactic2"],
    "techniques": [
      {"id": "T1234", "name": "Technique Name"}
    ]
  },

  "prerequisites": {
    "containers": ["container-name"],
    "network": "network_name"
  },

  "attack_flow": {
    "description": "Step-by-step attack description",
    "diagram": [
      "1. Step one",
      "2. Step two"
    ]
  },

  "phases": [
    {
      "name": "Phase Name",
      "description": "What this phase does",
      "critical": false,
      "actions": [
        {
          "type": "http_request|command|file_read|prompt",
          "target": "URL or file path",
          "method": "GET|POST",
          "expected_response_contains": ["string1", "string2"]
        }
      ]
    }
  ],

  "indicators_of_compromise": [
    {
      "type": "Network|File|Process",
      "description": "What to look for",
      "wazuh_rule": "100XXX"
    }
  ],

  "expected_wazuh_alerts": [
    {
      "rule_id": "100XXX",
      "level": 10,
      "description": "Alert description"
    }
  ],

  "remediation": {
    "immediate": ["Action 1", "Action 2"],
    "long_term": ["Fix 1", "Fix 2"]
  },

  "references": [
    {
      "title": "Reference Title",
      "url": "https://example.com"
    }
  ]
}
```

### Creating a New Scenario

1. **Create scenario file**:
```bash
mkdir -p scenarios/category-6-custom
touch scenarios/category-6-custom/s6-01-custom-attack.json
```

2. **Add the scenario JSON** following the structure above

3. **Create supporting scripts** (optional):
```bash
mkdir -p agents/cloud-workload/scripts
cat > agents/cloud-workload/scripts/simulate-custom-attack.sh << 'EOF'
#!/bin/bash
echo "Simulating custom attack..."
# Add attack simulation commands
EOF
chmod +x agents/cloud-workload/scripts/simulate-custom-attack.sh
```

4. **Test the scenario**:
```bash
python src/scenario-runner/runner.py --run S6-01 --dry-run
```

---

## Adding Custom Wazuh Rules

### Rule File Location
```
wazuh/rules/nhi-detection-rules.xml
```

### Rule Template
```xml
<group name="nhi_custom,">

  <!-- Base rule for matching log source -->
  <rule id="100XXX" level="5">
    <if_group>syslog</if_group>
    <match>custom_pattern</match>
    <description>NHI: Custom base detection</description>
    <group>nhi_custom,</group>
  </rule>

  <!-- Child rule for specific behavior -->
  <rule id="100XXY" level="10">
    <if_sid>100XXX</if_sid>
    <match>critical_pattern</match>
    <description>NHI: Critical custom detection</description>
    <mitre>
      <id>T1234</id>
    </mitre>
    <group>nhi_custom_critical,</group>
  </rule>

  <!-- Correlation rule -->
  <rule id="100XXZ" level="12" frequency="3" timeframe="60">
    <if_matched_sid>100XXX</if_matched_sid>
    <same_source_ip />
    <description>NHI: Repeated custom attack detected</description>
    <group>nhi_custom_correlation,</group>
  </rule>

</group>
```

### Rule Attributes

| Attribute | Description |
|-----------|-------------|
| `id` | Unique rule ID (100600-100999 for NHI) |
| `level` | Severity (0-15) |
| `frequency` | Number of matches required |
| `timeframe` | Seconds for frequency matching |
| `if_sid` | Parent rule ID |
| `if_group` | Parent rule group |
| `match` | Simple string matching |
| `regex` | Regular expression matching |
| `srcip` | Source IP pattern |
| `program_name` | Log source program |

### Testing Rules

```bash
# Test rule syntax
docker exec -it wazuh-manager /var/ossec/bin/wazuh-logtest

# Enter test log and press Enter
# Example:
# Jan  5 12:00:00 cloud-workload app: ACCESS 169.254.169.254/meta-data

# Reload rules
docker exec wazuh-manager /var/ossec/bin/wazuh-control reload
```

---

## Adding Custom Decoders

### Decoder Location
```
wazuh/decoders/nhi-decoders.xml
```

### Decoder Template
```xml
<!-- Base decoder -->
<decoder name="custom-app">
  <program_name>^custom-app$</program_name>
</decoder>

<!-- Field extraction decoder -->
<decoder name="custom-app-fields">
  <parent>custom-app</parent>
  <regex>ACTION (\S+) USER (\S+) IP (\S+)</regex>
  <order>action, user, srcip</order>
</decoder>

<!-- JSON decoder -->
<decoder name="custom-app-json">
  <parent>custom-app</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

---

## Adding New Agent Types

### Agent Dockerfile Template

```dockerfile
# agents/custom-agent/Dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install base packages
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    apt-transport-https \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Wazuh agent
ARG WAZUH_VERSION=4.9.2
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add - && \
    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | \
    tee /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y wazuh-agent=${WAZUH_VERSION}-1 && \
    rm -rf /var/lib/apt/lists/*

# Install custom tools
RUN apt-get update && apt-get install -y \
    your-custom-tool \
    && rm -rf /var/lib/apt/lists/*

# Copy configuration
COPY ossec.conf /var/ossec/etc/ossec.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
```

### Agent ossec.conf Template

```xml
<ossec_config>
  <client>
    <server>
      <address>wazuh-manager</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>wazuh-manager</manager_address>
      <port>1515</port>
      <agent_name>custom-agent</agent_name>
      <groups>custom,nhi</groups>
    </enrollment>
  </client>

  <!-- Custom log collection -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/custom-app/*.log</location>
  </localfile>

  <!-- Custom commands -->
  <localfile>
    <log_format>full_command</log_format>
    <command>custom-security-check.sh</command>
    <frequency>300</frequency>
  </localfile>
</ossec_config>
```

### Adding to Docker Compose

```yaml
# docker-compose.yml
services:
  custom-agent:
    build:
      context: ./agents/custom-agent
      args:
        - WAZUH_VERSION=${WAZUH_VERSION:-4.9.2}
    container_name: custom-agent
    hostname: custom-agent
    environment:
      - WAZUH_MANAGER=wazuh-manager
      - WAZUH_REGISTRATION_PASSWORD=${AGENT_REGISTRATION_PASSWORD:-SecretPassword}
    networks:
      cloud_net:
        ipv4_address: 172.41.0.40
    depends_on:
      - wazuh.manager
    profiles:
      - custom
```

---

## Adding Mock Services

### Mock Service Template

```python
#!/usr/bin/env python3
"""
Mock Custom Service
NDC Security 2026 - NHI Security Testbed
"""

from flask import Flask, request, jsonify
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mock-custom")

@app.route("/")
def index():
    return jsonify({
        "service": "Mock Custom Service",
        "endpoints": {
            "/api/sensitive": "Returns sensitive data"
        }
    })

@app.route("/api/sensitive")
def sensitive():
    logger.warning(f"SENSITIVE ACCESS from {request.remote_addr}")
    return jsonify({
        "secret": "DEMO_SECRET_12345",
        "api_key": "demo_key_for_testing"
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
```

### Mock Service Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY server.py .

EXPOSE 9000
CMD ["python", "server.py"]
```

---

## Integrating External Tools

### Falco Integration

```yaml
# Add Falco sidecar
services:
  falco:
    image: falcosecurity/falco:latest
    container_name: falco
    privileged: true
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock
      - /dev:/host/dev
      - /proc:/host/proc:ro
      - ./falco/rules:/etc/falco/rules.d
    networks:
      - mgmt_net
```

### Sending Falco Alerts to Wazuh

```yaml
# falco.yaml
json_output: true
json_include_output_property: true
http_output:
  enabled: true
  url: "http://wazuh-manager:55000/falco"
```

---

## Best Practices

### Scenario Design
1. Base scenarios on real-world attacks
2. Include MITRE ATT&CK mapping
3. Provide clear remediation steps
4. Test thoroughly before adding

### Rule Development
1. Start with low severity, increase after tuning
2. Use parent rules to avoid duplication
3. Include MITRE ATT&CK IDs
4. Document false positive sources

### Agent Configuration
1. Minimize installed tools
2. Use least privilege
3. Document log collection config
4. Include health check endpoints

---

## Contributing

To contribute scenarios, rules, or agents:

1. Fork the repository
2. Create a feature branch
3. Follow the templates above
4. Test thoroughly
5. Submit a pull request

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for details.
