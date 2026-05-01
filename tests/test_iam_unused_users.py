"""Tests for IAM unused users control check.

These tests exercise the structural contract of the finding dict and the
key behaviors (threshold, framework citations, evidence shape). They call
real AWS via the cloudguard profile, mirroring the rest of the suite.
"""
from src.checks.iam_unused_users import check_iam_unused_users


def test_unused_users_check_structure():
    """Finding should include all required fields with correct contract shape."""
    result = check_iam_unused_users()
    assert "control_id" in result
    assert "passed" in result
    assert "evidence" in result
    assert "framework_refs" in result
    assert "severity" in result
    assert result["control_id"] == "CC6.1-iam-unused-users"
    assert result["severity"] == "high"


def test_unused_users_framework_refs_include_pci():
    """PCI DSS 8.2.6 must be cited — the canonical user lifecycle requirement."""
    result = check_iam_unused_users()
    refs = result["framework_refs"]
    assert "soc2" in refs
    assert "pci_dss_4" in refs
    assert "cis_aws" in refs
    assert "nist_800_53" in refs
    assert "iso_27001" in refs
    assert "hipaa" in refs

    assert "8.2.6" in refs["pci_dss_4"], (
        "PCI DSS Req 8.2.6 (review user IDs every 6 months) is the canonical "
        "citation for unused-credential controls and must be present"
    )
    assert "1.12" in refs["cis_aws"], (
        "CIS AWS 1.12 (90-day inactivity) should be cited"
    )


def test_unused_users_evidence_documents_threshold_and_count():
    """Evidence must surface the threshold and the enumeration shape."""
    result = check_iam_unused_users()
    evidence = result["evidence"]

    has_enumeration = "total_users" in evidence and "user_findings" in evidence
    has_error = "error" in evidence
    assert has_enumeration or has_error

    if has_enumeration:
        assert isinstance(evidence["total_users"], int)
        assert evidence["total_users"] >= 0
        assert "inactivity_threshold_days" in evidence
        assert evidence["inactivity_threshold_days"] == 90


def test_unused_users_provides_remediation_when_failing():
    """Failing checks must provide actionable IAM-console remediation guidance."""
    result = check_iam_unused_users()
    if not result["passed"]:
        assert result["remediation"] is not None
        assert "IAM" in result["remediation"]
        assert len(result["remediation"]) > 30
