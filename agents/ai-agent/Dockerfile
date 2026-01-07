# AI Agent Container
# Demonstrates AI agent security vulnerabilities
# For NHI Security Testbed - NDC Security 2026
#
# Vulnerabilities demonstrated:
# - Prompt injection leading to credential disclosure
# - Excessive tool permissions
# - SSRF via HTTP tool
# - Memory poisoning

FROM python:3.11-slim

LABEL maintainer="Bodhisattva Das"
LABEL description="Vulnerable AI agent for NHI security testing"
LABEL version="1.0"

ARG WAZUH_VERSION=4.9.2

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies and Wazuh agent
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    apt-transport-https \
    lsb-release \
    ca-certificates \
    netcat-openbsd \
    procps \
    auditd \
    && rm -rf /var/lib/apt/lists/*

# Install Wazuh agent
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && apt-get install -y wazuh-agent=${WAZUH_VERSION}-1 \
    && rm -rf /var/lib/apt/lists/*

RUN update-rc.d wazuh-agent disable || true

# Setup application
WORKDIR /app

# Copy application code
COPY app/ /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy Wazuh configuration
COPY ossec.conf /var/ossec/etc/ossec.conf

# Create fake API keys for the agent (DEMO ONLY)
RUN mkdir -p /app/secrets \
    && echo "OPENAI_API_KEY=sk-demo-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" > /app/secrets/api_keys.env \
    && echo "DATABASE_PASSWORD=agent_db_secret_123" >> /app/secrets/api_keys.env

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python3", "agent.py"]
