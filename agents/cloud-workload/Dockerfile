# Cloud Workload Agent
# Simulates an Ubuntu-based cloud workload with Wazuh agent
# For NHI Security Testbed - NDC Security 2026

FROM ubuntu:22.04

LABEL maintainer="RUDRA Cybersecurity"
LABEL description="Cloud workload simulation with Wazuh agent for NHI security testing"
LABEL version="1.0"

ARG WAZUH_VERSION=4.9.2

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    apt-transport-https \
    lsb-release \
    ca-certificates \
    python3 \
    python3-pip \
    jq \
    netcat-openbsd \
    procps \
    iproute2 \
    dnsutils \
    vim \
    auditd \
    && rm -rf /var/lib/apt/lists/*

# Install AWS CLI (for demonstration of cloud SDK usage)
RUN pip3 install --no-cache-dir awscli boto3

# Install Wazuh agent
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && apt-get install -y wazuh-agent=${WAZUH_VERSION}-1 \
    && rm -rf /var/lib/apt/lists/*

# Disable automatic agent start (we'll start it manually in entrypoint)
RUN update-rc.d wazuh-agent disable || true

# Copy custom ossec.conf for NHI monitoring
COPY ossec.conf /var/ossec/etc/ossec.conf

# Create directories for demo scripts
RUN mkdir -p /opt/nhi-demo/scripts

# Copy demonstration scripts
COPY scripts/ /opt/nhi-demo/scripts/
RUN chmod +x /opt/nhi-demo/scripts/*.sh 2>/dev/null || true

# Create fake .aws credentials directory for demo
RUN mkdir -p /root/.aws \
    && echo "[default]" > /root/.aws/credentials \
    && echo "aws_access_key_id = AKIADEMONOTREAL12345" >> /root/.aws/credentials \
    && echo "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/DemoNotRealKey12345" >> /root/.aws/credentials

# Create fake .env file for demo
RUN echo "# Demo environment file - FAKE credentials" > /root/.env \
    && echo "DATABASE_URL=postgresql://admin:password123@db.example.com/mydb" >> /root/.env \
    && echo "API_SECRET=sk-demo-secret-key-not-real-12345" >> /root/.env

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set working directory
WORKDIR /opt/nhi-demo

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/var/ossec/logs/ossec.log"]
