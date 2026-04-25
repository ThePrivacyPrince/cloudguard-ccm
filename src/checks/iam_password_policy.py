"""IAM Password Policy control checks — SOC 2 CC6.1 / CIS AWS 1.8-1.9."""
from botocore.exceptions import ClientError

from src.aws_client import get_client


# Stricter than the CIS minimums — aligned with NIST 800-63B and PCI DSS 4.0.1
REQUIRED_MIN_LENGTH = 14
REQUIRED_MAX_PASSWORD_AGE_DAYS = 90
REQUIRED_PASSWORD_REUSE_PREVENTION = 24


def check_iam_password_policy(profile: str = "cloudguard") -> dict:
    """SOC 2 CC6.1 / CIS AWS 1.8-1.9 — IAM password policy enforces strong
    authentication for human IAM users.

    AWS does not enforce a password policy by default. Out of the box, an IAM
    user can have a single-character password. The account password policy
    must be explicitly configured.

    This check validates seven conditions against the account-level password
    policy:
      1. Policy exists at all
      2. Minimum length >= 14 (CIS 1.8 sets 14; PCI DSS 4.0.1 sets 12)
      3. Requires symbols
      4. Requires numbers
      5. Requires uppercase letters
      6. Requires lowercase letters
      7. Prevents password reuse for last 24 passwords (CIS 1.9)
      8. Maximum password age <= 90 days

    Returns:
        Finding dict. passed=True only if ALL conditions are satisfied.
    """
    iam = get_client("iam", profile=profile)

    try:
        response = iam.get_account_password_policy()
        policy = response.get("PasswordPolicy", {})
    except ClientError as e:
        # NoSuchEntity = no policy configured at all = immediate fail
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return _no_policy_finding()
        return _error_finding(str(e))

    # Evaluate each requirement
    checks = {
        "minimum_length": policy.get("MinimumPasswordLength", 0) >= REQUIRED_MIN_LENGTH,
        "requires_symbols": policy.get("RequireSymbols", False),
        "requires_numbers": policy.get("RequireNumbers", False),
        "requires_uppercase": policy.get("RequireUppercaseCharacters", False),
        "requires_lowercase": policy.get("RequireLowercaseCharacters", False),
        "password_reuse_prevention": (
            policy.get("PasswordReusePrevention", 0) >= REQUIRED_PASSWORD_REUSE_PREVENTION
        ),
        "max_password_age": (
            0 < policy.get("MaxPasswordAge", 0) <= REQUIRED_MAX_PASSWORD_AGE_DAYS
        ),
    }
    passed = all(checks.values())
    failed_checks = [name for name, ok in checks.items() if not ok]

    return {
        "control_id": "CC6.1-iam-password-policy",
        "framework_refs": _framework_refs(),
        "severity": "high",
        "passed": passed,
        "evidence": {
            "policy_configured": True,
            "current_minimum_length": policy.get("MinimumPasswordLength", 0),
            "current_max_password_age_days": policy.get("MaxPasswordAge", 0),
            "current_reuse_prevention": policy.get("PasswordReusePrevention", 0),
            "checks_results": checks,
            "failed_checks": failed_checks,
        },
        "remediation": (
            None if passed else
            "Update IAM password policy: IAM console → Account settings → "
            "Password policy → Edit. Set min length 14, require all character "
            "types, prevent reuse of last 24 passwords, max age 90 days."
        ),
    }


def _framework_refs() -> dict:
    """Shared framework mapping for IAM password policy controls."""
    return {
        "soc2": ["CC6.1", "CC6.6"],
        "pci_dss_4": ["8.3.6", "8.3.7", "8.3.9"],
        "cis_aws": ["1.8", "1.9"],
        "nist_800_53": ["IA-5(1)", "IA-5(4)"],
        "iso_27001": ["A.5.17", "A.8.5"],
        "hipaa": ["164.308(a)(5)(ii)(D)"],
    }


def _no_policy_finding() -> dict:
    """Return an unambiguous failure finding when no policy exists at all."""
    return {
        "control_id": "CC6.1-iam-password-policy",
        "framework_refs": _framework_refs(),
        "severity": "high",
        "passed": False,
        "evidence": {
            "policy_configured": False,
            "note": "No IAM password policy is configured for this account.",
        },
        "remediation": (
            "Create an IAM password policy: IAM console → Account settings → "
            "Password policy → Create. Set min length 14, require symbols, "
            "numbers, uppercase, lowercase, prevent reuse of last 24 passwords, "
            "max age 90 days."
        ),
    }


def _error_finding(error_msg: str) -> dict:
    """Return a failure finding when the API call itself fails."""
    return {
        "control_id": "CC6.1-iam-password-policy",
        "framework_refs": _framework_refs(),
        "severity": "high",
        "passed": False,
        "evidence": {"error": error_msg},
        "remediation": (
            "Verify cloudguard-scanner IAM user has iam:GetAccountPasswordPolicy "
            "permissions."
        ),
    }