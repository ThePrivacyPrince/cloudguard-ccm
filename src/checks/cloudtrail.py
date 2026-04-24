"""CloudTrail audit logging control checks — SOC 2 CC7.2 / CIS AWS 3.1-3.4."""
from botocore.exceptions import ClientError

from src.aws_client import get_client


def check_cloudtrail_enabled(profile: str = "cloudguard") -> dict:
    """SOC 2 CC7.2 / CIS AWS 3.1-3.4 — CloudTrail is enabled, multi-region,
    actively logging, and has log file validation enabled.

    CloudTrail is the foundation of AWS audit logging. Without it, there is
    no forensic record of API activity. This check validates four conditions
    against the account's trails:

      1. At least one trail exists (CIS 3.1)
      2. At least one trail is multi-region (CIS 3.1)
      3. At least one trail has log file validation enabled (CIS 3.2)
      4. At least one trail is actively logging (not stopped)

    A single trail meeting all four conditions satisfies this control. The
    check returns per-trail details in evidence for operator context.

    Returns:
        Finding dict with control_id, passed, evidence (per-trail breakdown),
        and remediation if any condition fails.
    """
    ct = get_client("cloudtrail", profile=profile)

    try:
        trails_response = ct.describe_trails(includeShadowTrails=False)
        trails = trails_response.get("trailList", [])
    except ClientError as e:
        return _error_finding(str(e))

    # Zero trails = immediate fail
    if not trails:
        return {
            "control_id": "CC7.2-cloudtrail-enabled",
            "framework_refs": _framework_refs(),
            "severity": "critical",
            "passed": False,
            "evidence": {
                "total_trails": 0,
                "trail_findings": [],
            },
            "remediation": (
                "Create a CloudTrail trail: CloudTrail console → Trails → "
                "Create trail. Enable 'Apply trail to all regions' and "
                "'Enable log file validation'. Direct logs to a dedicated "
                "S3 bucket with access logging enabled."
            ),
        }

    trail_findings = []
    any_compliant = False

    for trail in trails:
        name = trail.get("Name", "unknown")
        is_multi_region = trail.get("IsMultiRegionTrail", False)
        log_validation = trail.get("LogFileValidationEnabled", False)

        # Separate API call to check if trail is actively logging
        try:
            status = ct.get_trail_status(Name=trail["TrailARN"])
            is_logging = status.get("IsLogging", False)
        except ClientError as e:
            is_logging = False

        compliant = all([
            is_multi_region,
            log_validation,
            is_logging,
        ])

        trail_findings.append({
            "name": name,
            "is_multi_region": is_multi_region,
            "log_file_validation": log_validation,
            "is_logging": is_logging,
            "compliant": compliant,
        })

        if compliant:
            any_compliant = True

    return {
        "control_id": "CC7.2-cloudtrail-enabled",
        "framework_refs": _framework_refs(),
        "severity": "critical",
        "passed": any_compliant,
        "evidence": {
            "total_trails": len(trails),
            "trail_findings": trail_findings,
        },
        "remediation": (
            None if any_compliant else
            "At least one trail must satisfy ALL of: multi-region enabled, "
            "log file validation enabled, currently logging. Edit an existing "
            "trail or create a new one via CloudTrail console → Trails."
        ),
    }


def _framework_refs() -> dict:
    """Shared framework mapping for CloudTrail controls."""
    return {
        "soc2": ["CC7.2", "CC7.3"],
        "pci_dss_4": ["10.2.1", "10.3.1", "10.3.2"],
        "cis_aws": ["3.1", "3.2", "3.3", "3.4"],
        "nist_800_53": ["AU-2", "AU-3", "AU-12", "SI-4"],
        "iso_27001": ["A.8.15", "A.8.16"],
        "hipaa": ["164.312(b)", "164.308(a)(1)(ii)(D)"],
    }


def _error_finding(error_msg: str) -> dict:
    """Return a failure finding when the CloudTrail enumeration itself fails."""
    return {
        "control_id": "CC7.2-cloudtrail-enabled",
        "framework_refs": _framework_refs(),
        "severity": "critical",
        "passed": False,
        "evidence": {"error": error_msg},
        "remediation": (
            "Verify cloudguard-scanner IAM user has cloudtrail:DescribeTrails "
            "and cloudtrail:GetTrailStatus permissions."
        ),
    }