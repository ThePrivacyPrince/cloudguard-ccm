# CloudGuard — AWS Continuous Control Monitoring

> **TPRM Lifecycle Stage: Monitor** — Queries live AWS APIs to validate cloud control posture against six compliance frameworks on demand, replacing point-in-time screenshots with system-generated, hash-verified evidence.

## Problem This Solves

Traditional GRC programs capture screenshots during audit windows. By the time an auditor reviews them the configuration may have drifted — and there is no way to prove it hasn't. CloudGuard addresses this by:

- Querying AWS APIs directly via `boto3` — no screenshots, no manual exports
- Running every control check against six frameworks simultaneously so one scan produces evidence for SOC 2, PCI DSS, HIPAA, NIST, ISO 27001, and CIS in one pass
- Producing timestamped, tamper-evident output that auditors can verify with standard tooling (`shasum`)

## Controls Implemented

Five checks are currently working. A sixth (`check_root_access_keys`) is imported in `main.py` but the implementation file does not yet exist — the tool will not start until that file is created or the import is removed.

| Control ID | What it checks | Frameworks | Severity |
|---|---|---|---|
| CC6.1-root-mfa | Root account has MFA enabled | SOC 2 CC6.1, PCI 8.4.2/8.4.3, HIPAA 164.312(d), NIST IA-2(1), ISO A.5.17, CIS 1.5 | Critical |
| CC6.6-s3-public-access | All S3 buckets have Public Access Block fully configured | SOC 2 CC6.6, PCI 1.3.1/1.4.1, HIPAA 164.312(e), NIST AC-3, ISO A.8.20, CIS 2.1.5 | Critical |
| CC7.2-cloudtrail-enabled | CloudTrail multi-region logging active with log file validation | SOC 2 CC7.2, PCI 10.2/10.3, HIPAA 164.312(b), NIST AU-2/AU-3, ISO A.8.15, CIS 3.1–3.4 | Critical |
| CC6.1-iam-password-policy | IAM password policy meets 8 conditions (length, complexity, reuse, max age) | SOC 2 CC6.1, PCI 8.3.6/8.3.7/8.3.9, HIPAA 164.308(a)(5)(ii)(D), NIST IA-5(1), ISO A.5.17, CIS 1.8/1.9 | High |
| CC6.1-iam-unused-users | No IAM users have credentials (password or access key) unused for 90+ days | SOC 2 CC6.1, PCI 8.2.4/8.2.6, HIPAA 164.308(a)(3)(ii)(C), NIST AC-2/AC-2(3), ISO A.5.16/A.5.18, CIS 1.12 | High |

## Framework Coverage

Every check cites requirements across all six frameworks simultaneously:

| Framework | Families covered |
|---|---|
| SOC 2 TSC 2017 | Common Criteria CC6, CC7 |
| PCI DSS 4.0.1 | Requirements 1, 8, 10 |
| HIPAA Security Rule | 45 CFR 164.308, 164.312 |
| NIST SP 800-53 Rev. 5 | AC, IA, AU families |
| ISO 27001:2022 | Annex A controls |
| CIS AWS Foundations Benchmark | Sections 1, 2, 3 |

## How to Run

**Prerequisites:** Python 3.11+, an AWS profile named `cloudguard` with `ReadOnlyAccess`.

```bash
git clone https://github.com/ThePrivacyPrince/cloudguard-ccm.git
cd cloudguard-ccm
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# One-time: configure the read-only AWS profile
aws configure --profile cloudguard

# Terminal output (default)
python main.py

# PDF report → reports/cloudguard_report_<timestamp>.pdf
python main.py --pdf

# Tamper-evident evidence pack (PDF + manifest + zip + SHA-256 sidecar)
python main.py --pack

# Run tests
python -m pytest tests/ -v
```

> **Note:** `main.py` currently imports `check_root_access_keys` from a file that does not exist. The tool will crash at startup with `ModuleNotFoundError` until `src/checks/iam_root_access_keys.py` is created or the import is removed.

## Sample Terminal Output

```
CloudGuard — AWS Continuous Control Monitoring
Querying AWS for live control posture...

┌─────────────────────────────┬──────────┬────────┬─────────────────────────────────────────────────────────────┐
│ Control ID                  │ Severity │ Status │ Remediation                                                 │
├─────────────────────────────┼──────────┼────────┼─────────────────────────────────────────────────────────────┤
│ CC6.1-root-mfa              │ CRITICAL │  PASS  │ —                                                           │
│ CC6.6-s3-public-access      │ CRITICAL │  FAIL  │ Enable S3 Block Public Access on buckets: my-legacy-bucket  │
│ CC7.2-cloudtrail-enabled    │ CRITICAL │  PASS  │ —                                                           │
│ CC6.1-iam-password-policy   │ HIGH     │  FAIL  │ IAM → Account Settings → Edit password policy: min 14 chars │
│ CC6.1-iam-unused-users      │ HIGH     │  FAIL  │ Disable/delete stale credentials: user dev-svc (key unused  │
│                             │          │        │ 127 days)                                                   │
└─────────────────────────────┴──────────┴────────┴─────────────────────────────────────────────────────────────┘

Summary: 2/5 checks passed
```

## Evidence Pack Output

`--pack` writes four artifacts to `reports/`:

```
reports/
├── cloudguard_report_20260613_030000.pdf               # styled audit report
├── cloudguard_report_20260613_030000.manifest.json     # provenance + SHA-256 of every artifact
├── cloudguard_report_20260613_030000.evidence-pack.zip # PDF + manifest bundled
└── cloudguard_report_20260613_030000.evidence-pack.zip.sha256  # sidecar in sha256sum format
```

Verify integrity on any platform:

```bash
cd reports && shasum -a 256 -c *.evidence-pack.zip.sha256
```

## Architecture

```
cloudguard-ccm/
├── main.py                        # entry point — arg parsing, check runner, terminal renderer
├── requirements.txt
├── config/
│   └── controls.yaml              # placeholder for future declarative control definitions
├── src/
│   ├── aws_client.py              # boto3 session/client factory (profile-isolated)
│   ├── checks/
│   │   ├── iam_mfa.py             # CC6.1-root-mfa
│   │   ├── s3_public.py           # CC6.6-s3-public-access
│   │   ├── cloudtrail.py          # CC7.2-cloudtrail-enabled
│   │   ├── iam_password_policy.py # CC6.1-iam-password-policy
│   │   └── iam_unused_users.py    # CC6.1-iam-unused-users
│   └── reporters/
│       ├── pdf_reporter.py        # ReportLab PDF generation
│       └── manifest.py            # evidence pack builder (zip + SHA-256 sidecar)
└── tests/                         # pytest suite — one file per check module
    ├── conftest.py
    ├── test_iam_mfa.py
    ├── test_s3_public.py
    ├── test_cloudtrail.py
    ├── test_iam_password_policy.py
    ├── test_iam_unused_users.py
    ├── test_pdf_reporter.py
    └── test_manifest.py
```

## Security Design

CloudGuard practices what it checks:

- IAM user with `ReadOnlyAccess` — cannot modify or delete resources
- Credentials in `~/.aws/credentials` via profile isolation — never in code, env vars, or VCS
- `.gitignore` excludes secrets, virtual environments, reports output, and Python artifacts
- Every AWS API call in every check module is read-only

## Known Issues / What's Next

| Item | Status |
|---|---|
| `src/checks/iam_root_access_keys.py` missing | Breaks startup — needs implementation or import removal |
| `src/reporter.py`, `src/scorer.py` | Empty stubs — not wired into anything |
| `config/controls.yaml` | Empty placeholder |
| GitHub Actions scheduled nightly run | Not yet implemented |
| JSON output (`--json`) | Not yet implemented |
| Framework-specific filtering (`--framework hipaa`) | Not yet implemented |

## Background

This project operationalizes the continuous-monitoring thesis from my 2023 M.S. capstone, *"Cyber Threats and Partnerships: Tailoring a Third-Party Risk Management Program for PCI DSS Compliance"* (Utica University). The capstone argued that GRC programs must implement continuous monitoring systems to detect configuration drift; CloudGuard is the engineering implementation of that argument.

## Author

**Irvens Eristil** — GRC Engineer | PCI DSS · TPRM · Cloud Security
- LinkedIn: [linkedin.com/in/irvensjeffreyeristil](https://linkedin.com/in/irvensjeffreyeristil)
- Background: MLB (PCI DSS Level 1 Service Provider) · NYPA (700+ vendor TPRM program)
- Specialties: PCI DSS 4.0.1, SOC 2, TPRM, GRC automation

---

*CloudGuard is part of a portfolio demonstrating the transition from GRC analyst workflows to engineered, automated compliance tooling.*
