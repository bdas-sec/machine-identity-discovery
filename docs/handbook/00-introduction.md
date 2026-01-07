# Machine Identity Security Handbook

## Introduction

### What is Non-Human Identity (NHI) Security?

Non-Human Identities (NHIs) are the digital credentials and access mechanisms used by machines, applications, and automated systems rather than human users. These include:

- **API Keys & Tokens**: Static credentials used by applications to authenticate
- **Service Accounts**: Cloud provider identities assigned to compute resources
- **CI/CD Tokens**: Credentials used by build pipelines and deployment systems
- **Kubernetes Service Accounts**: Identity mechanisms for containerized workloads
- **AI Agent Credentials**: Access tokens and capabilities granted to autonomous AI systems

### Why NHIs Matter

**The Scale Problem**
- NHIs outnumber human identities by 45:1 in most enterprises
- A single cloud environment can have thousands of service accounts
- Each microservice may have multiple associated credentials

**The Visibility Gap**
- Traditional IAM focuses on human users
- NHIs are often created ad-hoc without governance
- No single system tracks all machine identities

**The Risk Amplification**
- NHIs rarely expire or rotate automatically
- Compromised NHIs provide persistent access
- NHIs often have over-privileged access
- AI agents create new attack vectors

### Attack Landscape

```
                    ┌─────────────────────────────────────┐
                    │         ATTACK SURFACE              │
                    ├─────────────────────────────────────┤
                    │                                     │
    ┌───────────────┼───────────────┬───────────────────┐│
    │               │               │                   ││
    ▼               ▼               ▼                   ▼│
┌───────┐    ┌───────────┐   ┌──────────┐      ┌────────┤│
│SECRETS│    │CLOUD IMDS │   │CI/CD     │      │AI AGENT││
│       │    │           │   │PIPELINES │      │SYSTEMS ││
│.env   │    │AWS/Azure  │   │          │      │        ││
│API    │    │Metadata   │   │GitHub    │      │Tool    ││
│Keys   │    │169.254... │   │GitLab    │      │Access  ││
└───────┘    └───────────┘   └──────────┘      └────────┘│
    │               │               │               │    │
    └───────────────┴───────────────┴───────────────┘    │
                    │                                     │
                    │     CREDENTIAL THEFT                │
                    │     PRIVILEGE ESCALATION            │
                    │     LATERAL MOVEMENT                │
                    │     SUPPLY CHAIN ATTACKS            │
                    └─────────────────────────────────────┘
```

### This Testbed

This testbed provides a safe, isolated environment to:

1. **Understand** how NHI attacks work
2. **Detect** NHI compromise using Wazuh SIEM
3. **Demonstrate** real-world attack scenarios
4. **Learn** remediation strategies

All credentials in this testbed are **FAKE** and designed for demonstration only.

### Who Should Use This

- **Security Engineers**: Understanding NHI attack patterns
- **DevOps Engineers**: Learning to secure CI/CD pipelines
- **Cloud Architects**: Implementing identity governance
- **Red Team**: Testing NHI detection capabilities
- **Blue Team**: Developing response playbooks

### Learning Objectives

After completing this training, you will be able to:

1. Identify the types of non-human identities in modern environments
2. Recognize common NHI attack patterns and techniques
3. Configure Wazuh to detect NHI-related threats
4. Investigate and respond to NHI security incidents
5. Implement security controls for machine identities

### Testbed Components

| Component | Purpose |
|-----------|---------|
| Wazuh Stack | SIEM for detection and alerting |
| Cloud Workload Agent | Simulates EC2-like workload |
| Vulnerable App | Demonstrates secret exposure |
| CI/CD Runner | Simulates GitHub/GitLab runner |
| K8s Node | Kubernetes workload simulation |
| AI Agent | Demonstrates AI security risks |
| Mock IMDS | AWS metadata service simulation |
| Mock CI/CD | GitHub/GitLab API simulation |

### Next Steps

1. [Installation Guide](02-installation.md) - Set up the testbed
2. [Architecture Overview](01-architecture.md) - Understand the components
3. [Scenario Catalog](04-scenario-catalog.md) - Run attack demonstrations
4. [Detection Rules](03-wazuh-rules-reference.md) - Review Wazuh rules

---

**NDC Security 2026**
"Who Gave the Agent Admin Rights?! Securing Cloud & AI Machine Identities"

*Presented by Bodhisattva Das*
