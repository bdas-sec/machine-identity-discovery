# Mock SPIRE Log Generator
# Replays realistic SPIRE Agent + Server log patterns for detection testing
# Based on real SPIRE 1.11.2 JSON log output
# For NHI Security Testbed

FROM python:3.11-slim

LABEL maintainer="Bodhisattva Das"
LABEL description="Mock SPIRE log generator for NHI security testing"
LABEL version="1.0"

WORKDIR /app

COPY spire_log_gen.py .

CMD ["python3", "-u", "spire_log_gen.py"]
