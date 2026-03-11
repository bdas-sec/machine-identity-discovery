# nhi-recon

Non-Human Identity reconnaissance and attack chain tool. The offensive companion to the NHI Security Testbed detection rules.

## Installation

```bash
pip install -e tools/nhi-recon/
```

## Usage

### Discover NHI credentials

```bash
# Scan for credential files, env vars, secrets
nhi-recon discover credentials -t cloud-workload
nhi-recon discover credentials -t cloud-workload --deep

# Probe cloud metadata services (IMDS)
nhi-recon discover imds -t localhost:1338

# Discover SPIFFE/SPIRE identities
nhi-recon discover spiffe -t localhost:8081

# Discover Kubernetes service accounts
nhi-recon discover kubernetes -t localhost:6443
```

### Enumerate permissions

```bash
# Auto-detect credential type and enumerate permissions
nhi-recon enumerate permissions -c "ASIADEMOTESTBED00001" -t localhost

# Scan for accessible NHI services
nhi-recon enumerate services -t localhost
```

### Attack chains

```bash
# IMDS to admin access
nhi-recon chain imds-to-admin -t localhost:1338

# CI/CD runner to cloud lateral movement
nhi-recon chain cicd-to-cloud -t localhost:1341

# SPIFFE selector spoofing
nhi-recon chain spiffe-spoofing -t localhost:8081

# Full kill chain (all stages)
nhi-recon chain full-killchain -t localhost
```

### Generate reports

```bash
# JSON report (default)
nhi-recon report generate -f json -o assessment

# HTML report (styled, for presentations)
nhi-recon report generate -f html -o assessment

# SARIF report (for CI/CD integration)
nhi-recon report generate -f sarif -o assessment
```

### Dashboard integration

Stream events to the testbed dashboard API for live visualization:

```bash
nhi-recon --dashboard-url http://localhost:8000 chain full-killchain -t localhost
```

Or set the environment variable:

```bash
export NHI_DASHBOARD_URL=http://localhost:8000
nhi-recon chain full-killchain -t localhost
```

### Global options

```
--target, -t         Default target host
--output, -o         Output format: text, json
--verbose, -v        Verbose output
--dashboard-url      Dashboard API URL for live event streaming
```

## Running against the testbed

Start the testbed, then run the full kill chain:

```bash
./scripts/start.sh
nhi-recon chain full-killchain -t localhost
nhi-recon report generate -f html -o testbed-assessment
```

## Report formats

| Format | Use case |
|--------|----------|
| JSON   | Programmatic consumption, dashboards |
| HTML   | Presentations, executive reports |
| SARIF  | GitHub Code Scanning, Azure DevOps, CI/CD pipelines |
