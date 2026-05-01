"""IAM unused user credentials control — SOC 2 CC6.1 / CIS AWS 1.12.

Validates that IAM users do not have credentials (passwords or access
keys) that have been unused for 90 days or longer. Stale credentials
are a leading cause of breaches: former employees whose accounts were
not deprovisioned, contractors whose engagements ended, service
accounts whose original purpose is forgotten. Each unused credential
is an unmonitored attack surface.

This check operationalizes the same PCI DSS Req 8.2.6 user account
lifecycle controls applied manually at MLB — codified here as
automated continuous monitoring.
"""
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from src.aws_client import get_client


# Stale-credential threshold per CIS AWS 1.12 and PCI DSS 8.2.6 guidance
INACTIVITY_THRESHOLD_DAYS = 90


def check_iam_unused_users(profile: str = "cloudguard") -> dict:
    """SOC 2 CC6.1 / CIS AWS 1.12 — IAM credentials unused for 90+ days.

    Enumerates all IAM users in the account and inspects each for:
      1. Console password last-used date (if a password is configured)
      2. Access key last-used date (for each active access key)

    A user is flagged if ANY active credential has not been used within
    the threshold window OR if the credential exists but has never been
    used at all (a strong stale-credential signal).

    Returns:
        Finding dict. passed=True only if all users have recent activity
        on every active credential (or if there are no users at all).
    """
    iam = get_client("iam", profile=profile)
    threshold = datetime.now(timezone.utc) - timedelta(days=INACTIVITY_THRESHOLD_DAYS)

    try:
        users = iam.list_users().get("Users", [])
    except ClientError as e:
        return _error_finding(str(e))

    user_findings = []
    any_stale = False

    for user in users:
        username = user["UserName"]
        stale_reasons = []

        # Console password staleness
        try:
            iam.get_login_profile(UserName=username)
            has_password = True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                has_password = False
            else:
                has_password = False

        if has_password:
            password_last_used = user.get("PasswordLastUsed")
            if password_last_used is None:
                stale_reasons.append("password configured but never used")
            elif password_last_used < threshold:
                age_days = (datetime.now(timezone.utc) - password_last_used).days
                stale_reasons.append(f"password unused for {age_days} days")

        # Access key staleness
        try:
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
        except ClientError:
            keys = []

        for key in keys:
            if key.get("Status") != "Active":
                continue
            key_id = key["AccessKeyId"]
            try:
                last_used_resp = iam.get_access_key_last_used(AccessKeyId=key_id)
                last_used = last_used_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
            except ClientError:
                last_used = None

            if last_used is None:
                stale_reasons.append(f"access key {key_id[-4:]} active but never used")
            elif last_used < threshold:
                age_days = (datetime.now(timezone.utc) - last_used).days
                stale_reasons.append(
                    f"access key {key_id[-4:]} unused for {age_days} days"
                )

        compliant = len(stale_reasons) == 0
        user_findings.append({
            "username": username,
            "compliant": compliant,
            "stale_reasons": stale_reasons,
        })
        if not compliant:
            any_stale = True

    # Zero users = zero exposure; pass
    passed = (not any_stale) if users else True

    return {
        "control_id": "CC6.1-iam-unused-users",
        "framework_refs": {
            "soc2": ["CC6.1", "CC6.6"],
            "pci_dss_4": ["8.2.4", "8.2.6"],
            "cis_aws": ["1.12"],
            "nist_800_53": ["AC-2", "AC-2(3)"],
            "iso_27001": ["A.5.16", "A.5.18"],
            "hipaa": ["164.308(a)(3)(ii)(C)"],
        },
        "severity": "high",
        "passed": passed,
        "evidence": {
            "total_users": len(users),
            "inactivity_threshold_days": INACTIVITY_THRESHOLD_DAYS,
            "user_findings": user_findings,
        },
        "remediation": (
            None if passed else
            "Disable or delete IAM users with stale credentials: IAM "
            "console -> Users -> select user -> Security credentials -> "
            "make password inactive AND deactivate stale access keys. "
            "For automation, document the joiner/mover/leaver workflow "
            "and review unused credentials quarterly."
        ),
    }


def _error_finding(error_msg: str) -> dict:
    return {
        "control_id": "CC6.1-iam-unused-users",
        "framework_refs": {
            "soc2": ["CC6.1"], "pci_dss_4": ["8.2.6"], "cis_aws": ["1.12"],
            "nist_800_53": ["AC-2"], "iso_27001": ["A.5.16"],
            "hipaa": ["164.308(a)(3)(ii)(C)"],
        },
        "severity": "high",
        "passed": False,
        "evidence": {"error": error_msg},
        "remediation": (
            "Verify cloudguard-scanner has iam:ListUsers, iam:GetLoginProfile, "
            "iam:ListAccessKeys, and iam:GetAccessKeyLastUsed permissions."
        ),
    }
