"""Tests for the CloudGuard PDF reporter.

These tests verify the reporter's contract — that it produces a non-empty
PDF file given a valid findings list, that it handles edge cases (zero
findings, missing account ID, mixed pass/fail), and that the output is a
valid PDF document. We deliberately do NOT test pixel-perfect rendering,
which is brittle; we test the integration contract.
"""
from pathlib import Path

import pytest

from src.reporters.pdf_reporter import (
    generate_pdf_report,
    _format_framework_refs,
)


# --- fixtures ------------------------------------------------------------

def _sample_finding(passed: bool = True, severity: str = "critical") -> dict:
    """Build a minimal finding dict for tests."""
    return {
        "control_id": "TEST-001",
        "framework_refs": {
            "soc2": ["CC6.1"],
            "pci_dss_4": ["8.4.2"],
            "cis_aws": ["1.5"],
            "nist_800_53": ["IA-2(1)"],
            "iso_27001": ["A.5.17"],
            "hipaa": ["164.312(d)"],
        },
        "severity": severity,
        "passed": passed,
        "evidence": {"sample": True},
        "remediation": None if passed else "Sample remediation text.",
    }


# --- public API contract -------------------------------------------------

def test_generate_pdf_creates_non_empty_file(tmp_path):
    """The reporter should write a non-empty PDF to the requested path."""
    findings = [_sample_finding(passed=True)]
    output = tmp_path / "test_report.pdf"

    result_path = generate_pdf_report(findings, output, account_id="123456789012")

    assert result_path == output
    assert output.exists()
    assert output.stat().st_size > 1000  # PDFs are at least a few KB


def test_generate_pdf_returns_valid_pdf_signature(tmp_path):
    """Output file should begin with the PDF magic bytes."""
    findings = [_sample_finding(passed=False)]
    output = tmp_path / "test_report.pdf"

    generate_pdf_report(findings, output)

    with open(output, "rb") as f:
        header = f.read(4)
    assert header == b"%PDF", f"Expected PDF magic bytes, got {header!r}"


def test_generate_pdf_handles_empty_findings(tmp_path):
    """Reporter should produce a valid PDF even when there are zero findings."""
    output = tmp_path / "empty_report.pdf"

    generate_pdf_report([], output)

    assert output.exists()
    assert output.stat().st_size > 1000


def test_generate_pdf_handles_mixed_pass_fail(tmp_path):
    """Reporter should render both passing and failing controls together."""
    findings = [
        _sample_finding(passed=True, severity="critical"),
        _sample_finding(passed=False, severity="high"),
        _sample_finding(passed=False, severity="critical"),
    ]
    output = tmp_path / "mixed_report.pdf"

    generate_pdf_report(findings, output, account_id="939139586118")

    assert output.exists()
    assert output.stat().st_size > 1000


def test_generate_pdf_works_without_account_id(tmp_path):
    """account_id is optional — reporter should not require it."""
    findings = [_sample_finding(passed=True)]
    output = tmp_path / "no_account_report.pdf"

    generate_pdf_report(findings, output)  # no account_id passed

    assert output.exists()


def test_generate_pdf_creates_parent_directory(tmp_path):
    """If the output directory doesn't exist, the reporter creates it."""
    nested_output = tmp_path / "nested" / "dir" / "report.pdf"
    findings = [_sample_finding(passed=True)]

    generate_pdf_report(findings, nested_output)

    assert nested_output.exists()


# --- internal helper unit tests ------------------------------------------

def test_format_framework_refs_includes_pci_when_present():
    """PCI mappings should always render in the citation string."""
    refs = {
        "soc2": ["CC6.1"],
        "pci_dss_4": ["8.4.2", "8.4.3"],
    }
    result = _format_framework_refs(refs)
    assert "PCI" in result
    assert "8.4.2" in result
    assert "8.4.3" in result


def test_format_framework_refs_handles_empty_dict():
    """Empty refs dict should produce a placeholder, not crash."""
    result = _format_framework_refs({})
    assert result == "—"


def test_format_framework_refs_orders_consistently():
    """Frameworks should appear in a stable order regardless of dict order."""
    refs_a = {"cis_aws": ["1.5"], "soc2": ["CC6.1"], "pci_dss_4": ["8.4.2"]}
    refs_b = {"pci_dss_4": ["8.4.2"], "soc2": ["CC6.1"], "cis_aws": ["1.5"]}
    assert _format_framework_refs(refs_a) == _format_framework_refs(refs_b)