"""Tests for the manifest / evidence pack module.

These tests verify the cryptographic and structural contract:
  - SHA-256 hashing is deterministic and matches universal known values
  - Manifest dicts contain every required field
  - Sidecar hash files are written in canonical sha256sum format
  - Evidence packs bundle the right artifacts together

We do NOT test against AWS — manifest generation is a pure function of
its inputs and produces no network calls.
"""
import json
import zipfile

import pytest

from src.reporters.manifest import (
    HASH_ALGORITHM,
    MANIFEST_SCHEMA_VERSION,
    build_evidence_pack,
    build_manifest,
    hash_bytes,
    hash_file,
    write_manifest_json,
    write_sidecar_hash,
)


# --- universal SHA-256 known-answer tests --------------------------------

def test_hash_bytes_empty_matches_universal_value():
    """The SHA-256 of empty bytes is one of the most well-known hashes."""
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert hash_bytes(b"") == expected


def test_hash_bytes_is_deterministic():
    """Same input must always produce same output."""
    data = b"CloudGuard test input"
    assert hash_bytes(data) == hash_bytes(data)


def test_hash_file_matches_hash_bytes(tmp_path):
    """File hashing should match in-memory hashing for the same content."""
    content = b"identical bytes for both paths"
    test_file = tmp_path / "sample.bin"
    test_file.write_bytes(content)

    assert hash_file(test_file) == hash_bytes(content)


def test_hash_file_handles_large_files(tmp_path):
    """Hashing should not OOM on large files (chunked reads work)."""
    test_file = tmp_path / "big.bin"
    test_file.write_bytes(b"x" * (2 * 1024 * 1024))  # 2 MB

    digest = hash_file(test_file)
    assert len(digest) == 64  # SHA-256 hex is always 64 chars
    assert all(c in "0123456789abcdef" for c in digest)


# --- manifest structure --------------------------------------------------

def _sample_finding(passed=True, severity="critical"):
    return {
        "control_id": "TEST-001",
        "framework_refs": {
            "soc2": ["CC6.1"],
            "pci_dss_4": ["8.4.2"],
            "cis_aws": ["1.5"],
        },
        "severity": severity,
        "passed": passed,
        "evidence": {},
        "remediation": None,
    }


def test_manifest_has_required_top_level_fields(tmp_path):
    """Every manifest must include schema, generator, timestamp, summary, artifacts."""
    pdf = tmp_path / "fake.pdf"
    pdf.write_bytes(b"fake pdf content")

    manifest = build_manifest(
        findings=[_sample_finding()],
        artifact_paths=[pdf],
        account_id="123456789012",
    )

    assert manifest["manifest_schema_version"] == MANIFEST_SCHEMA_VERSION
    assert manifest["hash_algorithm"] == HASH_ALGORITHM
    assert manifest["generator"] == "CloudGuard CCM"
    assert "generated_at_utc" in manifest
    assert "context" in manifest
    assert "summary" in manifest
    assert "artifacts" in manifest


def test_manifest_summary_counts_correctly(tmp_path):
    """Summary fields should accurately reflect the findings list."""
    pdf = tmp_path / "fake.pdf"
    pdf.write_bytes(b"x")

    findings = [
        _sample_finding(passed=True, severity="critical"),
        _sample_finding(passed=False, severity="high"),
        _sample_finding(passed=False, severity="critical"),
    ]
    manifest = build_manifest(findings, [pdf])

    assert manifest["summary"]["controls_evaluated"] == 3
    assert manifest["summary"]["controls_passed"] == 1
    assert manifest["summary"]["controls_failed"] == 2


def test_manifest_includes_pci_in_frameworks_cited(tmp_path):
    """PCI must surface in frameworks_cited when findings reference it."""
    pdf = tmp_path / "fake.pdf"
    pdf.write_bytes(b"x")

    manifest = build_manifest([_sample_finding()], [pdf])

    assert "pci_dss_4" in manifest["summary"]["frameworks_cited"]
    assert "soc2" in manifest["summary"]["frameworks_cited"]


def test_manifest_artifact_includes_sha256_hash(tmp_path):
    """Each artifact entry must include filename, size, and SHA-256."""
    pdf = tmp_path / "report.pdf"
    pdf.write_bytes(b"deterministic content")

    manifest = build_manifest([_sample_finding()], [pdf])

    assert len(manifest["artifacts"]) == 1
    artifact = manifest["artifacts"][0]
    assert artifact["filename"] == "report.pdf"
    assert artifact["size_bytes"] == len(b"deterministic content")
    assert len(artifact["sha256"]) == 64
    # Verify the hash is correct
    assert artifact["sha256"] == hash_bytes(b"deterministic content")


# --- write helpers -------------------------------------------------------

def test_write_manifest_json_produces_valid_json(tmp_path):
    """Written manifest should round-trip through json.load cleanly."""
    pdf = tmp_path / "fake.pdf"
    pdf.write_bytes(b"x")
    manifest = build_manifest([_sample_finding()], [pdf])

    output = tmp_path / "test.manifest.json"
    write_manifest_json(manifest, output)

    with open(output) as f:
        loaded = json.load(f)
    assert loaded == manifest


def test_write_sidecar_hash_uses_canonical_format(tmp_path):
    """Sidecar file should match `sha256sum` output format exactly."""
    target = tmp_path / "data.bin"
    target.write_bytes(b"verify me")

    sidecar = write_sidecar_hash(target)

    content = sidecar.read_text()
    expected_hash = hash_bytes(b"verify me")
    assert content == f"{expected_hash}  data.bin\n"
    # Two spaces between hash and filename is the GNU sha256sum standard
    assert "  " in content


# --- end-to-end evidence pack --------------------------------------------

def test_build_evidence_pack_produces_all_four_artifacts(tmp_path):
    """Full pack should produce PDF + manifest + zip + sidecar."""
    pdf = tmp_path / "cloudguard_report_test.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake report")

    artifacts = build_evidence_pack(
        pdf_path=pdf,
        findings=[_sample_finding()],
        output_dir=tmp_path,
        account_id="123456789012",
    )

    assert artifacts["pdf"].exists()
    assert artifacts["manifest"].exists()
    assert artifacts["zip"].exists()
    assert artifacts["sidecar"].exists()


def test_evidence_pack_zip_contains_pdf_and_manifest(tmp_path):
    """The bundled zip must contain both the PDF and the manifest."""
    pdf = tmp_path / "cloudguard_report_test.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake report")

    artifacts = build_evidence_pack(
        pdf_path=pdf,
        findings=[_sample_finding()],
        output_dir=tmp_path,
    )

    with zipfile.ZipFile(artifacts["zip"], "r") as zf:
        names = zf.namelist()
    assert "cloudguard_report_test.pdf" in names
    assert any(n.endswith(".manifest.json") for n in names)


def test_evidence_pack_sidecar_verifies_against_zip(tmp_path):
    """The sidecar hash must actually verify against the zip's real bytes."""
    pdf = tmp_path / "cloudguard_report_test.pdf"
    pdf.write_bytes(b"%PDF-1.4 fake report")

    artifacts = build_evidence_pack(
        pdf_path=pdf,
        findings=[_sample_finding()],
        output_dir=tmp_path,
    )

    # Recompute the zip's hash and confirm sidecar agrees
    actual_hash = hash_file(artifacts["zip"])
    sidecar_content = artifacts["sidecar"].read_text()
    assert sidecar_content.startswith(actual_hash)
