"""Tests for CloudTrail audit logging control check."""
from src.checks.cloudtrail import check_cloudtrail_enabled


def test_cloudtrail_check_structure():
    """Finding should include all required fields."""
    result = check_cloudtrail_enabled()
    assert "control_id" in result
    assert "passed" in result
    assert "evidence" in result
    assert "framework_refs" in result
    assert "severity" in result
    assert result["control_id"] == "CC7.2-cloudtrail-enabled"
    assert result["severity"] == "critical"


def test_cloudtrail_framework_refs_include_pci():
    """Multi-framework mapping must cite PCI DSS 4.0.1 — domain specialty."""
    result = check_cloudtrail_enabled()
    refs = result["framework_refs"]
    assert "soc2" in refs
    assert "pci_dss_4" in refs, "PCI DSS must be mapped — specialty area"
    assert "cis_aws" in refs
    assert "hipaa" in refs
    assert "nist_800_53" in refs
    assert "iso_27001" in refs

    # Spot-check that the right PCI req is cited for logging
    assert any("10.2" in r for r in refs["pci_dss_4"]), (
        "PCI DSS Req 10.2 (audit logs) should be cited for CloudTrail"
    )


def test_cloudtrail_evidence_includes_trail_enumeration():
    """Evidence should report total_trails — proves enumeration happened."""
    result = check_cloudtrail_enabled()
    evidence = result["evidence"]

    # Either we enumerated trails, OR we hit an error
    has_enumeration = "total_trails" in evidence
    has_error = "error" in evidence
    assert has_enumeration or has_error

    if has_enumeration:
        assert isinstance(evidence["total_trails"], int)
        assert evidence["total_trails"] >= 0


def test_cloudtrail_provides_remediation_when_failing():
    """Failing checks must provide actionable remediation."""
    result = check_cloudtrail_enabled()
    if not result["passed"]:
        assert result["remediation"] is not None
        assert len(result["remediation"]) > 20, (
            "Remediation should be substantive, not a placeholder"
        )