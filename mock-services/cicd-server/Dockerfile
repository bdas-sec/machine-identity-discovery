# Mock CI/CD Server
# Simulates GitHub Actions / GitLab CI API for token theft demos
# For NHI Security Testbed - NDC Security 2026

FROM python:3.11-slim

LABEL maintainer="Bodhisattva Das"
LABEL description="Mock CI/CD server for NHI security testing"
LABEL version="1.0"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

EXPOSE 8080

CMD ["python3", "server.py"]
