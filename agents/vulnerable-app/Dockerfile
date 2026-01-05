# Vulnerable Application Agent
# Intentionally contains security vulnerabilities for demonstration
# For NHI Security Testbed - NDC Security 2026
#
# WARNING: This container has INTENTIONAL vulnerabilities
# DO NOT use in production or expose to untrusted networks

FROM python:3.11-slim

LABEL maintainer="RUDRA Cybersecurity"
LABEL description="Intentionally vulnerable app for NHI security testing"
LABEL version="1.0"
LABEL warning="CONTAINS INTENTIONAL VULNERABILITIES - DEMO ONLY"

ARG WAZUH_VERSION=4.9.2

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies and Wazuh agent
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    apt-transport-https \
    lsb-release \
    ca-certificates \
    git \
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

# Disable automatic agent start
RUN update-rc.d wazuh-agent disable || true

# Setup application directory
WORKDIR /app

# Copy vulnerable application code
COPY app/ /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy Wazuh agent configuration
COPY ossec.conf /var/ossec/etc/ossec.conf

# Create .env file with FAKE secrets (INTENTIONALLY VULNERABLE)
RUN echo "# VULNERABLE - Secrets in .env file" > /app/.env \
    && echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" >> /app/.env \
    && echo "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" >> /app/.env \
    && echo "DATABASE_PASSWORD=super_secret_password_123" >> /app/.env \
    && echo "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" >> /app/.env \
    && echo "OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" >> /app/.env \
    && echo "STRIPE_SECRET_KEY=sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" >> /app/.env \
    && echo "SLACK_WEBHOOK=https://hooks.slack.com/services/T00/B00/XXXX" >> /app/.env

# Create fake git repository with secrets in history
RUN cd /app && git init \
    && git config user.email "dev@example.com" \
    && git config user.name "Developer" \
    && echo "API_KEY=sk-secret-removed-key-12345" > /app/old_config.txt \
    && git add . \
    && git commit -m "Initial commit with API key" \
    && rm /app/old_config.txt \
    && git add . \
    && git commit -m "Remove API key" || true

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose vulnerable app port
EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python3", "app.py"]
