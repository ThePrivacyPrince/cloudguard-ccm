# CloudGuard — AWS Continuous Control Monitoring

> Python-based tool that queries AWS APIs to automatically validate cloud configurations against **six security frameworks simultaneously** replacing point in time audits with on-demand, system-generated evidence.

## 🎯 Why This Exists

Traditional GRC relies on screenshots captured during audit cycles. By the time auditors review them, the configuration may have drifted. CloudGuard addresses this by:

- Querying AWS APIs directly via `boto3`
- Validating each control against multiple framework requirements at once
- Producing timestamped, reproducible findings on demand
- Outputting structured data that feeds downstream reporting and ticketing

One check → six frameworks of audit evidence.

## 🗺 Framework Mapping

Every control check in CloudGuard cites its requirement across:

| Framework | Coverage |
|---|---|
| SOC 2 TSC 2017 | Common Criteria (CC6, CC7) |
| **PCI DSS 4.0.1** | Requirements 1, 3, 7, 8 |
| HIPAA Security Rule | 45 CFR 164.312 |
| NIST 800-53 Rev. 5 | AC, IA, SC families |
| ISO 27001:2022 | Annex A controls |
| CIS AWS Foundations Benchmark | Technical guidance |

## ✅ Controls Implemented

| Control ID | Description | Frameworks | Severity |
|---|---|---|---|
| CC6.1-root-mfa | Root account has MFA enabled | SOC 2, PCI 8.4.2/8.4.3, HIPAA, NIST IA-2(1), ISO A.5.17, CIS 1.5 | Critical |
| CC6.6-s3-public-access | No S3 buckets allow public access | SOC 2, PCI 1.3.1/1.4.1, HIPAA, NIST AC-3, ISO A.8.20, CIS 2.1.5 | Critical |

## 🏗 Architecture
cloudguard-ccm/
├── src/
│   ├── aws_client.py      # boto3 session factory — profile-isolated, no hardcoded creds
│   └── checks/            # one module per control family
│       ├── iam_mfa.py     # IAM MFA validations
│       └── s3_public.py   # S3 public access validations
├── tests/                 # pytest suite (9 tests, 100% passing)
├── main.py                # entrypoint — runs checks, renders Rich table
└── config/controls.yaml   # future: declarative control definitions

## 🚀 Quick Start

```bash
git clone https://github.com/ThePrivacyPrince/cloudguard-ccm.git
cd cloudguard-ccm
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure AWS CLI with a read-only profile named "cloudguard"
aws configure --profile cloudguard

# Run the scanner
python main.py

# Run tests
python -m pytest tests/ -v
```

## 🔒 Security Design

CloudGuard **practices what it preaches**:
- IAM user with `ReadOnlyAccess` & cannot modify or destroy resources
- Credentials stored in `~/.aws/credentials` via profile isolation, never in code, env vars, or VCS
- `.gitignore` enforces exclusion of secrets, virtual environments, and Python artifacts
- Every control check is read-only and auditable

## 🗺 Roadmap

**Week 2:** CloudTrail enabled, IAM password policy, root access key checks, PDF report generator
**Week 3:** GitHub Actions scheduled nightly runs, JSON output for downstream tooling
**Week 4+:** Additional check families (VPC, RDS, KMS), HTML dashboard, framework-specific filtering (`--framework hipaa`)

## 📖 Research Foundation

This project operationalizes the continuous-monitoring thesis of my 2023 M.S. capstone, *"Cyber Threats and Partnerships: Tailoring a Third-Party Risk Management Program for PCI DSS Compliance"* (Utica University). Where the capstone argued that GRC programs must "implement continuous monitoring systems to detect and respond to vulnerabilities," CloudGuard is the engineering implementation.

## 👤 Author

**Irvens Eristil** — GRC Engineer | PCI DSS · TPRM · Cloud Security
- LinkedIn: [linkedin.com/in/irvensjeffreyeristil](https://linkedin.com/in/irvensjeffreyeristil)
- Background: MLB (PCI DSS Level 1 Service Provider) · NYPA (700+ vendor TPRM program)
- Specialties: PCI DSS 4.0.1, SOC 2, TPRM, GRC automation

---

*CloudGuard is part of a broader portfolio demonstrating the transition from GRC analyst workflows to engineered, automated compliance tooling.*