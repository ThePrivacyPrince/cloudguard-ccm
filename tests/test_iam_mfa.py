"""Tests for IAM MFA control check."""
from src.checks.iam_mfa import check_root_mfa


def test_root_mfa_check_structure():
    """Finding should include required fields."""
    result = check_root_mfa()
    assert "control_id" in result
    assert "passed" in result
    assert "evidence" in result
    assert "framework_refs" in result
    assert result["control_id"] == "CC6.1-root-mfa"


def test_root_mfa_passes_when_enabled():
    """Since we enabled root MFA Monday, this should return passed=True."""
    result = check_root_mfa()
    assert result["passed"] is True, (
        "Root MFA should be enabled. Re-enable via IAM console if this fails."
    )


def test_root_mfa_framework_refs():
    """Multi-framework mapping should include SOC 2, CIS, HIPAA, NIST, ISO, PCI."""
    result = check_root_mfa()
    refs = result["framework_refs"]
    assert "soc2" in refs
    assert "cis_aws" in refs
    assert "hipaa" in refs
    assert "nist_800_53" in refs
    assert "iso_27001" in refs
    assert "pci_dss_4" in refs  # Your domain specialty — never leave this out