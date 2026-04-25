"""Tests for IAM password policy control check."""
from src.checks.iam_password_policy import check_iam_password_policy


def test_password_policy_check_structure():
    """Finding should include all required fields with correct contract shape."""
    result = check_iam_password_policy()
    assert "control_id" in result
    assert "passed" in result
    assert "evidence" in result
    assert "framework_refs" in result
    assert "severity" in result
    assert result["control_id"] == "CC6.1-iam-password-policy"
    assert result["severity"] == "high"


def test_password_policy_framework_refs_include_pci():
    """Multi-framework mapping must cite PCI DSS 4.0.1 — domain specialty."""
    result = check_iam_password_policy()
    refs = result["framework_refs"]
    assert "soc2" in refs
    assert "pci_dss_4" in refs, "PCI DSS must be mapped — specialty area"
    assert "cis_aws" in refs
    assert "hipaa" in refs
    assert "nist_800_53" in refs
    assert "iso_27001" in refs

    # Spot-check that the right PCI requirements are cited for password policy
    assert any("8.3" in r for r in refs["pci_dss_4"]), (
        "PCI DSS Req 8.3.x (password requirements) should be cited"
    )
    assert any("1.8" in r or "1.9" in r for r in refs["cis_aws"]), (
        "CIS AWS 1.8/1.9 (password policy) should be cited"
    )


def test_password_policy_evidence_documents_state():
    """Evidence should clearly document whether a policy exists, plus per-check results."""
    result = check_iam_password_policy()
    evidence = result["evidence"]

    # Either we found a policy and have detailed checks, OR we documented its absence
    has_policy_state = "policy_configured" in evidence
    has_error = "error" in evidence
    assert has_policy_state or has_error

    # If the policy exists, we should have detailed sub-checks
    if evidence.get("policy_configured") is True:
        assert "checks_results" in evidence
        assert isinstance(evidence["checks_results"], dict)
        assert "minimum_length" in evidence["checks_results"]


def test_password_policy_provides_actionable_remediation_when_failing():
    """Failing checks must provide remediation that names IAM console steps."""
    result = check_iam_password_policy()
    if not result["passed"]:
        assert result["remediation"] is not None
        # Remediation should reference the IAM console for actionability
        assert "IAM" in result["remediation"]
        assert "Password policy" in result["remediation"]
        assert len(result["remediation"]) > 30, "Remediation should be substantive"