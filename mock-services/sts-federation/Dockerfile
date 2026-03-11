FROM python:3.12-slim

LABEL maintainer="Bodhisattva Das"
LABEL description="Mock STS Federation Service for NHI Security Testbed"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

EXPOSE 8091

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8091/health')" || exit 1

CMD ["python", "server.py"]
