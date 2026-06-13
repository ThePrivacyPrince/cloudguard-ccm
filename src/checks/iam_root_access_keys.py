"""IAM root access keys control — CIS AWS 1.4 / SOC 2 CC6.1.

Root user access keys grant unrestricted, permanent access to every AWS API
with no scope, no expiry, and no session boundary. CIS AWS Foundations 1.4
and PCI DSS 8.2.2 both require that no root access keys exist. The root
user should authenticate interactively with MFA when absolutely necessary;
programmatic keys for it have no legitimate operational use.

Uses iam.get_account_summary() — the same read-only call as the MFA check —
which returns AccountAccessKeysPresent == 1 if root keys exist, 0 if none.
"""
from src.aws_client import get_client


def check_root_access_keys(profile: str = "cloudguard") -> dict:
    """CIS AWS 1.4 / SOC 2 CC6.1 — Root user has no active access keys.

    Returns:
        Finding dict. passed=True only if AccountAccessKeysPresent == 0.
    """
    iam = get_client("iam", profile=profile)
    summary = iam.get_account_summary()
    keys_present = summary["SummaryMap"].get("AccountAccessKeysPresent", 0)
    passed = keys_present == 0

    return {
        "control_id": "CC6.1-root-access-keys",
        "framework_refs": {
            "soc2": ["CC6.1", "CC6.2"],
            "pci_dss_4": ["8.2.2", "8.6.1"],
            "cis_aws": ["1.4"],
            "nist_800_53": ["AC-2(9)", "IA-2", "AC-6(5)"],
            "iso_27001": ["A.5.17", "A.8.5"],
            "hipaa": ["164.312(a)(1)", "164.312(d)"],
        },
        "severity": "critical",
        "passed": passed,
        "evidence": {
            "AccountAccessKeysPresent": keys_present,
            "api_call": "iam.get_account_summary()",
        },
        "remediation": (
            None if passed else
            "Delete root user access keys immediately: IAM console → "
            "top-right account menu → Security credentials → Access keys → "
            "Delete. Root programmatic access has no legitimate use; "
            "use IAM roles or least-privilege IAM users instead."
        ),
    }
