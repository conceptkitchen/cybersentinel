# CyberSentinel

**AI-Powered Multi-Agent Security Operations Center**

Built for the AWS x Anthropic x Datadog GenAI Hackathon (Feb 2026)

## What It Does

CyberSentinel is a multi-agent cybersecurity system that coordinates 4 specialized AI agents across the NIST Cybersecurity Framework controls:

1. **Detection Agent** (DETECT) - Threat hunting, IOC identification, anomaly detection
2. **Prevention Agent** (PROTECT) - Firewall rules, WAF policies, security group hardening
3. **Response Agent** (RESPOND) - Incident triage, containment, forensics coordination
4. **Recovery Agent** (RECOVER) - System restoration, backup verification, post-incident review

A **SOC Commander** orchestrates all agents using a deterministic Graph workflow with conditional routing based on threat severity.

## Tech Stack

- **Amazon Bedrock** - Claude Sonnet as the reasoning engine for all agents
- **Strands Agents SDK** - Multi-agent orchestration (Graph + Swarm patterns)
- **Datadog MCP** - Observability integration (metrics, logs, monitors, incidents)
- **FastAPI + WebSocket** - Real-time War Room dashboard backend
- **React + Tailwind** - War Room visualization frontend

## Architecture

```
                         ┌─────────────────────┐
     Security Alert ───▶ │    SOC Commander     │
                         │   (Graph Orchestrator)│
                         └──────────┬───────────┘
                                    │
               ┌────────────────────┼────────────────────┐
               │                    │                    │
     ┌─────────▼──────┐   ┌────────▼────────┐   ┌──────▼─────────┐
     │   Detection     │   │   Prevention    │   │   Response     │
     │   Agent         │   │   Agent         │   │   Agent        │
     │                 │   │                 │   │                │
     │ - Threat Hunt   │   │ - Firewall Mgmt │   │ - Containment  │
     │ - IOC Analysis  │   │ - WAF Rules     │   │ - Forensics    │
     │ - Log Triage    │   │ - SG Hardening  │   │ - Triage       │
     └────────┬────────┘   └────────┬────────┘   └───────┬────────┘
              │                     │                     │
              └─────────────────────┼─────────────────────┘
                                    │
                          ┌─────────▼──────────┐
                          │   Recovery Agent    │
                          │                    │
                          │ - System Restore   │
                          │ - Backup Verify    │
                          │ - Post-Incident    │
                          └─────────┬──────────┘
                                    │
                          ┌─────────▼──────────┐
                          │   Datadog MCP      │
                          │   (Observability)  │
                          └────────────────────┘
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials (for Bedrock)
aws configure

# Run a demo scenario
python run.py --scenario ransomware

# Run with the War Room dashboard
python run.py --scenario ransomware --war-room
```

## Demo Scenarios

| Scenario | Description | Agents Activated |
|----------|-------------|------------------|
| `ransomware` | Ransomware on production DB server | All 4 agents |
| `data_exfil` | Data exfiltration via compromised IAM | Detection, Response, Recovery |
| `brute_force` | Distributed SSH/API brute force | Detection, Prevention |

## Project Structure

```
cybersentinel/
├── run.py                    # Main entry point + CLI
├── agents/
│   ├── __init__.py
│   ├── detection.py          # DETECT - Threat hunting & IOC analysis
│   ├── prevention.py         # PROTECT - Firewall & WAF management
│   ├── response.py           # RESPOND - Incident triage & containment
│   ├── recovery.py           # RECOVER - System restoration
│   └── orchestrator.py       # SOC Commander (Graph workflow)
├── tools/
│   ├── __init__.py
│   ├── aws_security.py       # AWS GuardDuty, SecurityHub, WAF stubs
│   ├── forensics.py          # Forensics & investigation tools
│   └── infrastructure.py     # Infrastructure management tools
├── mock_datadog_mcp.py       # Mock Datadog MCP server (no account needed)
├── server/
│   ├── __init__.py
│   └── app.py                # FastAPI + WebSocket War Room backend
├── war-room/                 # React War Room dashboard
│   └── index.html            # Single-file React app
├── scenarios/
│   ├── __init__.py
│   ├── ransomware.py
│   ├── data_exfil.py
│   └── brute_force.py
└── requirements.txt
```

## NIST CSF Mapping

| NIST Function | CyberSentinel Agent | Key Capabilities |
|---------------|--------------------|-----------------|
| DETECT | Detection Agent | Anomaly detection, IOC correlation, threat intelligence enrichment |
| PROTECT | Prevention Agent | Automated firewall rules, WAF policy updates, security group hardening |
| RESPOND | Response Agent | Incident classification, evidence collection, containment actions |
| RECOVER | Recovery Agent | Service restoration, backup integrity verification, lessons learned |

## Built By

**RJ Moscardon** - The Concept Kitchen
- Top 8 Finalist, 2026 Frontier Tower AI Hackathon (CSI project)
- Security+ Certified
- GitHub: [@conceptkitchen](https://github.com/conceptkitchen)
