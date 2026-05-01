"""Evidence pack integrity manifest generator.

Produces tamper-evident manifests for CloudGuard evidence packs. Each
manifest is a JSON document containing provenance metadata and SHA-256
hashes of every artifact in the pack. Pairs with a sidecar `.sha256`
file containing the hash of the manifest itself, providing chain-of-
custody integrity for downstream auditors.

Design principle: the manifest is the contract between the system and
the auditor. An evidence pack that cannot be integrity-verified is not
evidence — it is an unsigned claim. CloudGuard rejects the unsigned
claim and produces hash-verified output by default.
"""
import hashlib
import json
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


MANIFEST_SCHEMA_VERSION = "1.0"
HASH_ALGORITHM = "sha256"
GENERATOR_NAME = "CloudGuard CCM"


# --- core hashing primitives ---------------------------------------------

def hash_file(path: Path) -> str:
    """Compute the SHA-256 hash of a file as a 64-char hex string.

    Reads the file in 64 KB chunks to handle arbitrarily large files
    without loading them entirely into memory.
    """
    path = Path(path)
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def hash_bytes(data: bytes) -> str:
    """Compute the SHA-256 hash of an in-memory byte string."""
    return hashlib.sha256(data).hexdigest()


# --- manifest construction -----------------------------------------------

def build_manifest(
    findings: list[dict],
    artifact_paths: list[Path],
    account_id: str = None,
) -> dict:
    """Assemble the manifest dict for an evidence pack.

    Args:
        findings: list of finding dicts (used for provenance metadata).
        artifact_paths: files included in the pack to be hashed.
        account_id: optional AWS account ID for context.

    Returns:
        A manifest dict ready to be JSON-serialized.
    """
    framework_counter = Counter()
    for f in findings:
        for key in f.get("framework_refs", {}):
            framework_counter[key] += 1

    severity_counter = Counter(
        f.get("severity", "unknown").lower() for f in findings
    )

    artifacts = []
    for path in artifact_paths:
        path = Path(path)
        artifacts.append({
            "filename": path.name,
            "size_bytes": path.stat().st_size,
            "sha256": hash_file(path),
        })

    total = len(findings)
    passed = sum(1 for f in findings if f.get("passed"))

    return {
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "hash_algorithm": HASH_ALGORITHM,
        "generator": GENERATOR_NAME,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "context": {
            "aws_account_id": account_id,
        },
        "summary": {
            "controls_evaluated": total,
            "controls_passed": passed,
            "controls_failed": total - passed,
            "frameworks_cited": sorted(framework_counter.keys()),
            "severity_distribution": dict(severity_counter),
        },
        "artifacts": artifacts,
    }


def write_manifest_json(manifest: dict, output_path: Path) -> Path:
    """Serialize a manifest to JSON on disk with deterministic key ordering.

    Deterministic ordering matters for hash stability — re-serializing
    the same manifest must produce the same bytes, otherwise the
    sidecar `.sha256` will not verify.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(manifest, indent=2, sort_keys=True)
    output_path.write_text(serialized, encoding="utf-8")
    return output_path


def write_sidecar_hash(file_path: Path) -> Path:
    """Write a sidecar `.sha256` file next to the given file.

    The sidecar contains the hash followed by two spaces and the
    filename, matching the format produced by the standard `sha256sum`
    Unix utility — so any auditor can verify with:

        sha256sum -c <filename>.sha256
    """
    file_path = Path(file_path)
    sidecar_path = file_path.with_suffix(file_path.suffix + ".sha256")
    digest = hash_file(file_path)
    sidecar_content = f"{digest}  {file_path.name}\n"
    sidecar_path.write_text(sidecar_content, encoding="utf-8")
    return sidecar_path


# --- evidence pack assembly ----------------------------------------------

def build_evidence_pack(
    pdf_path: Path,
    findings: list[dict],
    output_dir: Path,
    account_id: str = None,
) -> dict:
    """Assemble a complete evidence pack alongside an existing PDF report.

    Produces:
      - <stem>.manifest.json — provenance + per-artifact hashes
      - <stem>.evidence-pack.zip — bundled PDF + manifest
      - <stem>.evidence-pack.zip.sha256 — sidecar hash of the zip

    Args:
        pdf_path: path to the already-generated PDF report.
        findings: the finding list that produced the PDF (for manifest).
        output_dir: directory where pack artifacts will be written.
        account_id: optional AWS account ID for manifest context.

    Returns:
        A dict with paths to all four artifacts (pdf, manifest, zip, sidecar).
    """
    pdf_path = Path(pdf_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    stem = pdf_path.stem  # e.g. cloudguard_report_20260501_113045
    manifest_path = output_dir / f"{stem}.manifest.json"
    zip_path = output_dir / f"{stem}.evidence-pack.zip"

    # 1. Build and write the manifest covering the PDF
    manifest = build_manifest(
        findings=findings,
        artifact_paths=[pdf_path],
        account_id=account_id,
    )
    write_manifest_json(manifest, manifest_path)

    # 2. Bundle the PDF + manifest into a zip
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(pdf_path, arcname=pdf_path.name)
        zf.write(manifest_path, arcname=manifest_path.name)

    # 3. Write the sidecar hash for the zip itself
    sidecar_path = write_sidecar_hash(zip_path)

    return {
        "pdf": pdf_path,
        "manifest": manifest_path,
        "zip": zip_path,
        "sidecar": sidecar_path,
    }
