"""S3 public access control checks — SOC 2 CC6.6 / CIS AWS 2.1.5."""
from botocore.exceptions import ClientError
from src.aws_client import get_client


def check_s3_public_access_block(profile: str = "cloudguard") -> dict:
    """SOC 2 CC6.6 / CIS AWS 2.1.5 — No S3 buckets allow public access.

    Checks every bucket in the account for its Public Access Block configuration.
    A bucket is considered compliant if all 4 public-access settings are True:
      - BlockPublicAcls
      - IgnorePublicAcls
      - BlockPublicPolicy
      - RestrictPublicBuckets

    Returns:
        Finding dict. passed=True only if ALL buckets are fully blocked
        (or no buckets exist at all, which means no exposure).
    """
    s3 = get_client("s3", profile=profile)

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        return _error_finding(str(e))

    bucket_findings = []
    all_compliant = True

    for bucket in buckets:
        name = bucket["Name"]
        try:
            pab = s3.get_public_access_block(Bucket=name)
            cfg = pab["PublicAccessBlockConfiguration"]
            compliant = all([
                cfg.get("BlockPublicAcls", False),
                cfg.get("IgnorePublicAcls", False),
                cfg.get("BlockPublicPolicy", False),
                cfg.get("RestrictPublicBuckets", False),
            ])
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                compliant = False
                cfg = {"note": "No Public Access Block configured"}
            else:
                compliant = False
                cfg = {"error": str(e)}

        bucket_findings.append({
            "bucket": name,
            "compliant": compliant,
            "config": cfg,
        })
        if not compliant:
            all_compliant = False

    passed = all_compliant if buckets else True

    return {
        "control_id": "CC6.6-s3-public-access",
        "framework_refs": {
            "soc2": ["CC6.6"],
            "pci_dss_4": ["1.3.1", "1.4.1", "3.3.1"],
            "cis_aws": ["2.1.5"],
            "nist_800_53": ["AC-3", "AC-4", "SC-7"],
            "iso_27001": ["A.5.10", "A.8.3", "A.8.20"],
            "hipaa": ["164.312(a)(1)", "164.312(e)(1)"],
        },
        "severity": "critical",
        "passed": passed,
        "evidence": {
            "total_buckets": len(buckets),
            "bucket_findings": bucket_findings,
        },
        "remediation": (
            None if passed else
            "For each non-compliant bucket: S3 console → bucket → Permissions → "
            "Block public access → Edit → enable all four settings → save."
        ),
    }


def _error_finding(error_msg: str) -> dict:
    return {
        "control_id": "CC6.6-s3-public-access",
        "severity": "critical",
        "passed": False,
        "evidence": {"error": error_msg},
        "remediation": "Verify cloudguard-scanner has s3:ListBuckets and s3:GetBucketPublicAccessBlock permissions.",
    }