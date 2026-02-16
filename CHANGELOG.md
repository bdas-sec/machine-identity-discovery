# Changelog

All notable changes to the NHI Security Testbed are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased] — Phase 3: SIEM Expansion & Product Polish

### Added
- OCSF (Open Cybersecurity Schema Framework) event class mapping for normalised telemetry across SIEM platforms
- Kubernetes container escape detection rules (MITRE ATT&CK T1611)
- 5 new attack scenarios: OAuth token theft, GCP Workload Identity Federation abuse, mock OAuth provider, extended CI/CD and GCP WIF endpoints
- Prometheus metrics exporter and Grafana dashboards for testbed observability
- Helm chart for Kubernetes-native deployment
- Scenario scheduling automation for continuous detection validation
- NHI Detection Rule Pack — distributable archive of all rules

### Changed
- Upgraded all 11 decoders to production-grade (JSON parsing, field extraction, timestamp normalisation)
- Detection coverage matrix updated with new scenarios and rules

### In Progress
- Mock OAuth provider and GCP WIF endpoint extensions
- E2E tests for 5 new scenarios and K8s escape rules
- Prometheus, Helm chart, and Podman compatibility testing

---

## [0.2.0] — 2026-02-10 — Phase 2: Multi-SIEM & API Layer

### Added
- **Sigma rule conversion pipeline**: 62 Sigma rules across 7 categories (credential discovery, cloud IMDS, Kubernetes, CI/CD, AI agents, secret patterns, correlation) via pySigma with custom backends
- **FastAPI REST API**: Scaffold with routes for health, scenarios, rules, and alerts (`api/main.py`); Pydantic models; async Wazuh client integration; auto-generated OpenAPI docs at `/docs` and `/redoc`
- **pySigma conversion pipeline**: `scripts/sigma_convert.py` converts Sigma YAML to Splunk SPL, Microsoft Sentinel KQL, and Wazuh XML with category filtering and statistics reporting
- **E2E test suite**: 133 test methods across 5 categories achieving 95.8% end-to-end detection coverage; only S1-05 (Kubernetes Config Discovery) untested
- **Alert validation loop**: End-to-end verification that attack scenarios trigger expected Wazuh alerts
- **5 missing scenario JSONs**: Filled gaps to bring scenario count from 19 to 24 (S1-05, S2-05, S3-04, S3-05, S4-05)
- **AI agent detection rules expanded**: 5 → 10 dedicated rules covering shell execution, network commands, credential file access, prompt injection, IMDS SSRF, rapid file operations, MCP tool use, external network requests
- **Secret pattern detection expanded**: 6 → 15 patterns including Azure connection strings, JWT tokens, database DSNs, Stripe API keys, Twilio API keys, Firebase server keys, Terraform Cloud tokens, Vault service tokens, Datadog API keys
- **Correlation rule testing**: All 5 correlation rules (100950-100954) validated with automated tests
- **Test infrastructure**: `tests/conftest.py` with session-scoped fixtures for Docker client, Wazuh API/Indexer clients, HTTP clients, scenario loader, alert validator; `tests/helpers/` with shared utilities
- **CI/CD workflow**: `.github/workflows/test.yml` with unit, rule-validation, integration, and E2E (matrix by category) jobs
- **Detection coverage report**: `tests/reports/detection_coverage.md` and `detection_coverage.json` with automated generation via `generate_coverage_matrix.py`

### Changed
- **README redesign**: Added badges (Wazuh 4.9.2, MITRE ATT&CK, Docker Compose, scenario/rule counts), kill chain table, architecture section, scenario reference table, detection rules reference
- **Wazuh rules expanded**: 48 → 62 rules in `wazuh/rules/nhi-detection-rules.xml`
- **Project packaging**: `pyproject.toml` with hatchling build system, optional dependency groups (api, sigma, test, dev, all), ruff/mypy configuration, pytest markers

### Fixed
- Scenario JSON consistency — all 24 scenarios now follow uniform structure with `mitre_attack`, `phases`, `expected_wazuh_alerts`, and `demo_script` fields
- Wazuh multi-root XML handling in CI tests and workflow validation

---

## [0.1.0] — 2026-01-15 — Phase 1: Conference Demo

### Added
- **Docker Compose testbed**: 11 services across 4 isolated networks (`mgmt_net`, `cloud_net`, `cicd_net`, `k8s_net`) simulating cloud infrastructure, CI/CD pipelines, Kubernetes clusters, and Wazuh SIEM management plane
- **48 Wazuh detection rules**: Custom rules in ID range 100600-100999 covering credential discovery, IMDS abuse, service account misuse, Kubernetes security, CI/CD pipeline attacks, AI agent anomalies, secret patterns, and correlation
- **19 attack scenarios**: JSON-defined scenarios across 5 categories (Secrets, Cloud, CI/CD, Kubernetes, AI Agents) with MITRE ATT&CK mappings
- **Demo runner**: `run_demo.py` — type-safe scenario runner supporting individual, level-based, and full-suite execution of all 24 defined scenarios
- **Health check**: `health_check.py` — automated service verification with auto-fix capabilities for agent enrollment and group creation
- **Wazuh agent containers**: cloud-workload, vulnerable-app, cicd-runner, k8s-node-1, k8s-node-2, ai-agent — each with role-specific configurations
- **Mock services**: AWS IMDS simulation (port 1338), HashiCorp Vault in dev mode (port 8200), mock CI/CD server (port 8080)
- **Vulnerable application**: Intentionally insecure Flask app (port 8888) with SSRF endpoints, exposed `.env` files, and hardcoded credentials
- **Lifecycle scripts**: `scripts/start.sh` (auto-detects Podman/Docker, creates Wazuh groups, deploys stack), `scripts/stop.sh`, `scripts/offensive-demo.sh`
- **Workshop handbook**: 8-chapter documentation covering introduction, architecture, installation, rule reference, scenario catalog, detection playbook, remediation guide, and testbed extension
- **Conference materials**: CyberWiseCon Europe 2026 presentation (10-minute screen-recorded demo), NDC Security 2026 talk materials
- **5 kill chain stages**: Discovery → Credential Theft → Privilege Escalation → Lateral Movement → Persistence, mapped to MITRE ATT&CK techniques (T1190, T1552.001, T1552.005, T1078.004, T1528, T1195.002, T1078, T1136)
- **Conference abstracts**: 45-minute talk, 2-hour workshop, 10-minute lightning talk — targeting Black Hat, DEF CON, BSides, OWASP, KubeCon, fwd:cloudsec, RSA
- **Product strategy**: Purple Team Framework positioning ("Atomic Red Team for NHI"), open-core licensing model, competitive analysis of 9 funded NHI startups ($240M+ combined)
- **Technical exploration**: Codebase maturity audit (70% production-ready), 8 critical gaps identified, 4-phase productisation roadmap

### Known Issues
- Decoders at demo-grade only (simple prematch, limited field extraction)
- 19 of 24 scenario JSONs present (5 missing)
- E2E test coverage at 21% (Category 1 only)
- All detection rules Wazuh-specific (no SIEM portability)
- No REST API for programmatic access
