"""IAM MFA control checks — SOC 2 CC6.1 / CIS AWS Benchmark 1.5."""
from src.aws_client import get_client


def check_root_mfa(profile: str = "cloudguard") -> dict:
    """SOC 2 CC6.1 / CIS AWS 1.5 — Is MFA enabled for the AWS root user?

    Root is the most privileged AWS identity. Its credentials cannot be
    scoped or time-limited like an IAM user's. MFA is the last line of
    defense against a compromised root password.

    Uses iam.get_account_summary(), which returns a SummaryMap dict where
    AccountMFAEnabled == 1 if root MFA is on, 0 if off.

    Returns:
        Finding dict with control_id, passed, evidence, remediation.
    """
    iam = get_client("iam", profile=profile)
    summary = iam.get_account_summary()
    mfa_flag = summary["SummaryMap"].get("AccountMFAEnabled", 0)
    passed = mfa_flag == 1

    return {
        "control_id": "CC6.1-root-mfa",
        "framework_refs": {
            "soc2": ["CC6.1", "CC6.6"],
            "pci_dss_4": ["8.4.2", "8.4.3", "8.3.1"],
            "cis_aws": ["1.5"],
            "nist_800_53": ["IA-2(1)", "IA-2(2)", "AC-2"],
            "iso_27001": ["A.5.17", "A.8.5"],
            "hipaa": ["164.312(a)(2)(i)", "164.312(d)"],
        },
        "severity": "critical",
        "passed": passed,
        "evidence": {
            "AccountMFAEnabled": mfa_flag,
            "api_call": "iam.get_account_summary()",
        },
        "remediation": (
            None if passed else
            "Enable MFA on the root user: IAM console → "
            "Security credentials → Assign MFA device."
        ),
    }