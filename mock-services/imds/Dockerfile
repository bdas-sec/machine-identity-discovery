# Mock IMDS Service
# Simulates AWS/Azure Instance Metadata Service for credential theft demos
# For NHI Security Testbed - NDC Security 2026

FROM python:3.11-slim

LABEL maintainer="RUDRA Cybersecurity"
LABEL description="Mock Instance Metadata Service for NHI security testing"
LABEL version="1.0"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY server.py .

EXPOSE 1338

CMD ["python3", "server.py"]
