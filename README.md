# CloudGuard — AWS Continuous Control Monitoring

> Python-based tool that continuously validates AWS accounts against SOC 2 Common Criteria and CIS AWS Foundations Benchmark controls, replacing point-in-time audits with on-demand, system-generated evidence.

## Status
🚧 Under active development — Week 1 of build

## Research Foundation
This project operationalizes the continuous monitoring thesis of my 2023 M.S. capstone, *"Cyber Threats and Partnerships: Tailoring a Third-Party Risk Management Program for PCI DSS Compliance"* (Utica University).

## Architecture (planned)
- `src/aws_client.py` — boto3 session factory using named AWS profiles
- `src/checks/` — one module per control family (IAM, S3, CloudTrail, ...)
- `config/controls.yaml` — declarative control definitions mapped to frameworks
- `src/reporter.py` — findings → JSON + PDF exec summary

## Author
Irvens Eristil — GRC Engineer | PCI DSS · TPRM · Cloud Security
