"""Tests for S3 public access control check."""
from src.checks.s3_public import check_s3_public_access_block


def test_s3_check_structure():
    """Finding should include required fields."""
    result = check_s3_public_access_block()
    assert "control_id" in result
    assert "passed" in result
    assert "evidence" in result
    assert "framework_refs" in result
    assert result["control_id"] == "CC6.6-s3-public-access"


def test_s3_framework_refs_include_pci():
    """Multi-framework mapping should cite PCI DSS — Frost's domain specialty."""
    result = check_s3_public_access_block()
    refs = result["framework_refs"]
    assert "soc2" in refs
    assert "pci_dss_4" in refs
    assert "cis_aws" in refs
    assert "hipaa" in refs
    assert "nist_800_53" in refs
    assert "iso_27001" in refs


def test_s3_evidence_reports_bucket_count():
    """Evidence should show total_buckets count — proves the check enumerated."""
    result = check_s3_public_access_block()
    assert "total_buckets" in result["evidence"]
    assert isinstance(result["evidence"]["total_buckets"], int)