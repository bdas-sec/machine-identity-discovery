# Kubernetes Node Agent
# Simulates a Kubernetes worker node with Wazuh agent
# For NHI Security Testbed - NDC Security 2026

FROM ubuntu:22.04

LABEL maintainer="RUDRA Cybersecurity"
LABEL description="Kubernetes node simulation for NHI security testing"
LABEL version="1.0"

ARG WAZUH_VERSION=4.9.2

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    apt-transport-https \
    lsb-release \
    ca-certificates \
    jq \
    netcat-openbsd \
    procps \
    auditd \
    && rm -rf /var/lib/apt/lists/*

# Install kubectl for demonstration
RUN curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.29/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.29/deb/ /" | tee /etc/apt/sources.list.d/kubernetes.list \
    && apt-get update \
    && apt-get install -y kubectl \
    && rm -rf /var/lib/apt/lists/*

# Install Wazuh agent
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && apt-get install -y wazuh-agent=${WAZUH_VERSION}-1 \
    && rm -rf /var/lib/apt/lists/*

RUN update-rc.d wazuh-agent disable || true

# Create simulated Kubernetes service account directory
RUN mkdir -p /var/run/secrets/kubernetes.io/serviceaccount

# Create fake service account token (JWT format - DEMO ONLY)
RUN echo "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlbW8ifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCJ9.DEMO_SIGNATURE" > /var/run/secrets/kubernetes.io/serviceaccount/token

# Create namespace and CA cert
RUN echo "default" > /var/run/secrets/kubernetes.io/serviceaccount/namespace
RUN echo "-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIJANHDEMO0CERT0MA0GCSqGSIb3DQEBCwUAMCcxJTAjBgNV
BAMMHGt1YmVybmV0ZXMtZGVtby1jYS5sb2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAw
-----END CERTIFICATE-----" > /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Create fake kubeconfig
RUN mkdir -p /root/.kube \
    && echo 'apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://kubernetes.default.svc:443
    certificate-authority: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  name: local
contexts:
- context:
    cluster: local
    user: default
  name: default
current-context: default
users:
- name: default
  user:
    tokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token' > /root/.kube/config

# Create fake secrets mount (simulating secret volume)
RUN mkdir -p /var/run/secrets/app \
    && echo "db_password=super_secret_db_pass" > /var/run/secrets/app/database-secret \
    && echo "api_key=sk-demo-kubernetes-secret" > /var/run/secrets/app/api-key

# Copy Wazuh configuration
COPY ossec.conf /var/ossec/etc/ossec.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /root

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/var/ossec/logs/ossec.log"]
