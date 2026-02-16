# Mock OAuth Provider
# Simulates OAuth2/OIDC provider for consent phishing demos
# For NHI Security Testbed - NDC Security 2026

FROM python:3.11-slim

LABEL maintainer="Bodhisattva Das"
LABEL description="Mock OAuth/OIDC provider for NHI security testing"
LABEL version="1.0"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY server.py .

EXPOSE 8090

CMD ["python3", "server.py"]
