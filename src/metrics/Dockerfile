# NHI Security Testbed - Prometheus Metrics Exporter
# Collects detection coverage, alert, and service health metrics
# For NHI Security Testbed - NDC Security 2026

FROM python:3.11-slim

LABEL maintainer="Bodhisattva Das"
LABEL description="Prometheus metrics exporter for NHI Security Testbed"
LABEL version="0.1.0"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY exporter.py .

EXPOSE 9091

HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9091/health')" || exit 1

CMD ["python3", "exporter.py"]
