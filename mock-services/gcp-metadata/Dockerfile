# Mock GCP Metadata Service
# Simulates GCP Compute Engine metadata + Workload Identity Federation
# For NHI Security Testbed - NDC Security 2026

FROM python:3.11-slim

LABEL maintainer="Bodhisattva Das"
LABEL description="Mock GCP metadata service for NHI security testing"
LABEL version="1.0"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY server.py .

EXPOSE 1339

CMD ["python3", "server.py"]
