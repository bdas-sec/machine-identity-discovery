FROM python:3.12-slim

LABEL org.opencontainers.image.title="NHI Security Operator" \
      org.opencontainers.image.description="Kubernetes operator for NHI purple team automation" \
      org.opencontainers.image.source="https://github.com/yourorg/nhi-testbed" \
      org.opencontainers.image.vendor="NHI Security Testbed"

WORKDIR /app

# Install dependencies first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY operator.py .

# Run as non-root
RUN useradd --create-home --uid 1000 operator
USER 1000

CMD ["kopf", "run", "operator.py", "--verbose", "--all-namespaces"]
