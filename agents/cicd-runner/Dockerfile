# CI/CD Runner Agent
# Simulates a GitHub Actions / GitLab CI runner with Wazuh agent
# For NHI Security Testbed - NDC Security 2026

FROM ubuntu:22.04

LABEL maintainer="RUDRA Cybersecurity"
LABEL description="CI/CD runner simulation for NHI security testing"
LABEL version="1.0"

ARG WAZUH_VERSION=4.9.2

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies including common CI/CD tools
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    apt-transport-https \
    lsb-release \
    ca-certificates \
    git \
    docker.io \
    nodejs \
    npm \
    python3 \
    python3-pip \
    jq \
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

# Setup runner workspace (similar to GitHub Actions _work directory)
RUN mkdir -p /runner/_work /runner/scripts /runner/.credentials

# Create fake runner credentials (INTENTIONALLY EXPOSED)
RUN echo '{"runner_id": "12345", "runner_name": "self-hosted-runner-01"}' > /runner/.credentials/runner_id.json \
    && echo "RUNNER_TOKEN=AABCDEFGHIJKLMNOPQRSTUVWXYZ234567" > /runner/.credentials/.runner \
    && echo "ACTIONS_RUNTIME_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo.token" > /runner/.credentials/.token

# Create fake .npmrc with auth token
RUN echo "//registry.npmjs.org/:_authToken=npm_XXXXXXXXXXXXXXXXXXXX" > /root/.npmrc

# Create fake .docker/config.json with registry auth
RUN mkdir -p /root/.docker \
    && echo '{"auths":{"ghcr.io":{"auth":"ZGVtbzpkZW1vX3Rva2Vu"},"docker.io":{"auth":"ZGVtbzpkZW1vX3Bhc3M="}}}' > /root/.docker/config.json

# Copy Wazuh agent configuration
COPY ossec.conf /var/ossec/etc/ossec.conf

# Copy runner scripts
COPY scripts/ /runner/scripts/
RUN chmod +x /runner/scripts/*.sh 2>/dev/null || true

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /runner

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/var/ossec/logs/ossec.log"]
