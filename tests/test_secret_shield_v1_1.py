"""
ISO 9001:2015 Agile V Verification Suite for AGY Secret Shield v1.1.0 Features.
Tests dynamic secret detection (JWT, PKCS#8/OpenSSH, fine-grained GitHub PATs),
full git history scanning, OASIS SARIF 2.1.0 report export, and batch DPAPI quarantine rotation.

NOTE: All test fixtures are synthesized dynamically at runtime using string concatenation
to prevent static repository hygiene scanners from triggering false positives.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from agy_secret_shield.l1_primitives import (
    batch_dpapi_seal,
    batch_dpapi_unseal,
    rotate_dpapi_quarantine,
    scan_text_for_secrets,
)
from agy_secret_shield.l3_pipeline import (
    SecretShieldPipeline,
    export_sarif_report,
    scan_git_history,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _build_dynamic_jwt() -> str:
    h = ".".join([
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ])
    return h


def _build_dynamic_pkcs8() -> str:
    lines = [
        "-----" + "BEGIN PRIVATE KEY" + "-----",
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5testKeyBlob==",
        "-----" + "END PRIVATE KEY" + "-----",
    ]
    return "\n".join(lines)


def _build_dynamic_openssh() -> str:
    lines = [
        "-----" + "BEGIN OPENSSH PRIVATE KEY" + "-----",
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn",
        "-----" + "END OPENSSH PRIVATE KEY" + "-----",
    ]
    return "\n".join(lines)


def _build_dynamic_github_pat() -> str:
    prefix = "".join(["git", "hub_pat_"])
    body = "".join(["11AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPP", "QQRRSSTTUUVVWWXXYYZZ0011223344556677889900aa"])
    return prefix + body


def test_v1_1_jwt_detection_dynamic() -> None:
    jwt_token = _build_dynamic_jwt()
    sample_text = f"Authorization: Bearer {jwt_token}\nDEBUG=false\n"
    res = scan_text_for_secrets(sample_text)
    assert res["clean"] is False
    assert res["finding_count"] >= 1
    rule_ids = {f["rule_id"] for f in res["findings"]}
    assert "jwt_token" in rule_ids
    assert "[REDACTED_DPAPI:" in res["sanitized_text"]


def test_v1_1_pkcs8_and_openssh_detection_dynamic() -> None:
    pkcs8_key = _build_dynamic_pkcs8()
    openssh_key = _build_dynamic_openssh()
    text = f"# Config file\nPKCS8_BLOB:\n{pkcs8_key}\nOPENSSH_BLOB:\n{openssh_key}\n"
    res = scan_text_for_secrets(text)
    assert res["clean"] is False
    rule_ids = {f["rule_id"] for f in res["findings"]}
    assert "pkcs8_private_key" in rule_ids or "private_key_pem" in rule_ids


def test_v1_1_github_fine_grained_pat_detection_dynamic() -> None:
    pat = _build_dynamic_github_pat()
    text = f"GH_TOKEN={pat}\n"
    res = scan_text_for_secrets(text)
    assert res["clean"] is False
    rule_ids = {f["rule_id"] for f in res["findings"]}
    assert "github_fine_grained_pat" in rule_ids


def test_v1_1_batch_dpapi_quarantine_rotation() -> None:
    secrets = [
        "".join(["sec", "ret_token_one_123456"]),
        "".join(["sec", "ret_token_two_654321"]),
        "".join(["sec", "ret_token_three_abcdef"]),
    ]

    envelopes = batch_dpapi_seal(secrets, description_prefix="test-batch")
    assert len(envelopes) == 3
    for env in envelopes:
        assert "ciphertext_b64" in env
        assert "sha256" in env

    recovered = batch_dpapi_unseal(envelopes)
    assert recovered == secrets

    # Perform rotation
    rotated_envelopes = rotate_dpapi_quarantine(envelopes)
    assert len(rotated_envelopes) == 3

    recovered_after_rotation = batch_dpapi_unseal(rotated_envelopes)
    assert recovered_after_rotation == secrets


def test_v1_1_scan_git_history_on_repo() -> None:
    history_res = scan_git_history(REPO_ROOT, max_commits=30)
    assert isinstance(history_res, dict)
    assert "commits_scanned" in history_res
    assert history_res["commits_scanned"] > 0
    assert "clean" in history_res
    assert "flagged_commits" in history_res


def test_v1_1_export_sarif_report_schema() -> None:
    jwt_token = _build_dynamic_jwt()
    pipeline = SecretShieldPipeline()
    audit_res = pipeline.audit_target(custom_text=f"Bearer {jwt_token}\n")

    sarif = pipeline.export_sarif(audit_res)
    assert sarif["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "agy-secret-shield"
    assert driver["version"] == "1.1.0"
    assert len(driver["rules"]) >= 8

    results = sarif["runs"][0]["results"]
    assert len(results) >= 1
    assert results[0]["ruleId"] == "jwt_token"
    assert "locations" in results[0]
