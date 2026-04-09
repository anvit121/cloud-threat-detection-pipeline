# ☁️ Cloud Threat Detection Pipeline (AWS)

> **Real-time threat detection for AWS environments using CloudTrail, CloudWatch, and Lambda — with MITRE ATT&CK-mapped detection rules and multi-factor risk scoring.**

[![CI/CD](https://github.com/YOUR_USERNAME/cloud-threat-detection/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/YOUR_USERNAME/cloud-threat-detection/actions)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://python.org)
[![Coverage](https://img.shields.io/badge/coverage-85%25-green.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Overview

This project implements a **production-grade cloud threat detection pipeline** on AWS that ingests CloudTrail API logs in real time, applies modular detection rules mapped to the [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/), scores each finding using a multi-factor risk engine, and routes prioritized alerts to SNS, SQS, and DynamoDB.

The pipeline processes thousands of log events per invocation and generates actionable, prioritized alerts — reducing analyst fatigue by surfacing the highest-risk findings first.

---

## Architecture

```
CloudTrail (Multi-Region)
        │ API logs (all management events)
        ▼
CloudWatch Logs (/aws/cloudtrail/...)
        │ Subscription Filter (all events)
        ▼
Lambda (Python 3.12) ←── CloudFormation IaC
        │
        ├── EventParser        → Decode CloudTrail Records batch
        ├── DetectorChain      → 4 modular threat detectors
        │     ├── PrivilegeEscalationDetector   (MITRE T1098)
        │     ├── UnusualRegionDetector          (MITRE T1535)
        │     ├── CredentialAbuseDetector        (MITRE T1078)
        │     └── DataExfiltrationDetector       (MITRE T1530)
        ├── RiskScorer         → 0-100 multi-factor risk score
        └── AlertManager       → Severity-based routing
              ├── SNS Topic    → Email / PagerDuty / Slack
              ├── SQS FIFO     → SIEM / ticketing integration
              └── DynamoDB     → Audit trail (90-day TTL)
```

---

## Detection Coverage

| Detector | MITRE Technique | Severity Range | Description |
|---|---|---|---|
| **Privilege Escalation** | T1098, T1078.004 | MEDIUM → CRITICAL | IAM policy attachments, role manipulation, access key creation |
| **Unusual Region** | T1535 | MEDIUM → CRITICAL | API calls from non-baseline AWS regions |
| **Credential Abuse** | T1078, T1552 | MEDIUM → CRITICAL | Root usage, IAM recon, no-MFA console logins |
| **Data Exfiltration** | T1530, T1562.008 | LOW → CRITICAL | S3 exposure, secrets access, CloudTrail deletion |

### Risk Scoring

Each finding receives a composite **0–100 risk score** using:

- **Base score** from severity (CRITICAL=90, HIGH=70, MEDIUM=45, LOW=20)
- **+/- modifiers** for contextual factors (root account, dangerous policy, off-hours activity, failed attempts)
- **Deduplication** within execution window to reduce alert noise

```
CRITICAL ≥ 80   →  SNS + SQS + DynamoDB (immediate page)
HIGH     60–79  →  SNS + SQS + DynamoDB
MEDIUM   40–59  →  SQS + DynamoDB
LOW      0–39   →  DynamoDB only
```

---

## Project Structure

```
cloud-threat-detection/
├── src/
│   ├── lambda_handler.py           # Lambda entry point
│   ├── detectors/
│   │   ├── privilege_escalation.py # IAM privilege escalation (15 rules)
│   │   ├── unusual_region.py       # Non-baseline region detection
│   │   ├── credential_abuse.py     # Root, recon, credential ops
│   │   └── data_exfiltration.py    # S3, secrets, defense evasion
│   ├── processors/
│   │   ├── event_parser.py         # CloudTrail JSON parsing
│   │   └── risk_scorer.py          # Multi-factor risk engine
│   ├── alerts/
│   │   └── alert_manager.py        # SNS/SQS/DynamoDB routing
│   └── utils/
│       └── logger.py               # Structured JSON logging
├── infrastructure/
│   └── cloudformation/
│       └── threat-detection-stack.yaml   # Full IaC (CloudTrail → Lambda → SNS)
├── tests/
│   └── unit/
│       └── test_detectors.py       # 25+ unit tests, 85%+ coverage
├── scripts/
│   ├── deploy.sh                   # One-command deployment
│   └── generate_test_events.py     # Synthetic attack scenario generator
├── .github/
│   └── workflows/
│       └── ci-cd.yml               # Lint → Test → Build → Deploy pipeline
└── requirements.txt
```

---

## Quick Start

### Prerequisites
- Python 3.12+
- AWS CLI v2 configured (`aws configure`)
- An S3 bucket for Lambda code artifacts
- Permissions: CloudFormation, Lambda, IAM, CloudTrail, CloudWatch, SNS, SQS, DynamoDB

### 1. Clone and install

```bash
git clone https://github.com/YOUR_USERNAME/cloud-threat-detection.git
cd cloud-threat-detection
pip install -r requirements.txt
```

### 2. Run the tests

```bash
PYTHONPATH=src pytest tests/ -v --cov=src --cov-report=term-missing
```

### 3. Deploy to AWS

```bash
export LAMBDA_CODE_BUCKET=your-deployment-bucket
export ALERT_EMAIL=security@yourcompany.com
export BASELINE_REGIONS="us-east-1,us-west-2"

./scripts/deploy.sh dev your-aws-profile us-east-1
```

The script will:
1. Run unit tests
2. Package Lambda + dependencies into a zip
3. Upload to S3
4. Deploy the CloudFormation stack (creates all AWS resources)
5. Update the Lambda function code

### 4. Test with synthetic events

```bash
python scripts/generate_test_events.py
```

This generates a realistic CloudWatch Logs payload containing four attack scenarios:
- **Privilege escalation chain** (recon → CreateAccessKey → AttachAdminPolicy)
- **Unusual region activity** (EC2 + secrets access from Africa/APAC)
- **Defense evasion** (StopLogging + DeleteTrail)
- **Root account usage** (creating backdoor user)

---

## Detection Examples

### Privilege Escalation → Administrator Access

```json
{
  "finding_type": "PRIVILEGE_ESCALATION",
  "severity": "CRITICAL",
  "risk_score": 97,
  "mitre_technique": "T1098.003",
  "action": "iam:AttachUserPolicy",
  "actor": "arn:aws:iam::123456789012:user/eve-attacker",
  "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
  "source_ip": "203.0.113.42",
  "region": "us-east-1",
  "risk_factors": ["privilege_escalation_action", "dangerous_policy_arn"],
  "remediation": "Review and revoke the policy attachment. Audit IAM user permissions."
}
```

### Defense Evasion — CloudTrail Deletion

```json
{
  "finding_type": "DEFENSE_EVASION_LOGGING_DISRUPTION",
  "severity": "CRITICAL",
  "risk_score": 100,
  "mitre_technique": "T1562.008",
  "action": "cloudtrail:DeleteTrail",
  "risk_factors": ["defense_evasion", "logging_disruption", "covering_tracks"],
  "remediation": "IMMEDIATE ACTION REQUIRED: Re-enable CloudTrail. Treat as active incident."
}
```

---

## Infrastructure as Code

All AWS resources are defined in `infrastructure/cloudformation/threat-detection-stack.yaml`:

| Resource | Description |
|---|---|
| `AWS::CloudTrail::Trail` | Multi-region trail with S3 + CloudWatch delivery |
| `AWS::S3::Bucket` | Encrypted trail storage with lifecycle policies |
| `AWS::Logs::LogGroup` | CloudTrail log group (90-day retention) |
| `AWS::Logs::SubscriptionFilter` | Real-time Lambda trigger |
| `AWS::Lambda::Function` | Python 3.12 detection engine |
| `AWS::SNS::Topic` | High-severity alert notifications |
| `AWS::SQS::Queue` | FIFO queue for SIEM integration |
| `AWS::DynamoDB::Table` | Findings audit trail with TTL |
| `AWS::CloudWatch::Alarm` | Operational monitoring |

---

## CI/CD Pipeline

GitHub Actions workflow (`.github/workflows/ci-cd.yml`):

```
push to main
    ↓
Lint (flake8, black, bandit)
    ↓
Unit Tests (pytest + coverage)
    ↓
CloudFormation Validate
    ↓
Build Lambda Package
    ↓
Deploy to Staging (auto)
```

---

## Security Considerations

- Lambda execution role follows **least privilege** — only permissions it needs
- CloudTrail log bucket has **public access blocked** and **server-side encryption**
- SNS and SQS use **AWS KMS encryption**
- DynamoDB has **encryption at rest** and **point-in-time recovery**
- All IAM policies are **inline** (no managed policy attachment to Lambda)
- CloudTrail log file **integrity validation** enabled

---

## Future Enhancements

- [ ] **ML-based anomaly detection** using SageMaker for baseline modeling
- [ ] **IP reputation enrichment** via threat intel feeds (VirusTotal, AbuseIPDB)
- [ ] **Impossible travel detection** using DynamoDB session correlation
- [ ] **Cross-account support** via AWS Organizations + EventBridge
- [ ] **Automated remediation** (Lambda → SSM Run Command to isolate instances)
- [ ] **SOAR integration** via Splunk SOAR / Tines webhooks
- [ ] **Terraform module** alternative to CloudFormation

---

## License

MIT License — see [LICENSE](LICENSE)

---

*Built to demonstrate production-grade AWS threat detection engineering using CloudTrail, CloudWatch, Lambda, and the MITRE ATT&CK framework.*