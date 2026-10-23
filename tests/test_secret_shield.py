"""ISO 9001:2015 / Agile V Locked Test Suite for agy-secret-shield (BL-20261023-SHIELD-L4).

Covers architectural tiers L1 -> L2 -> L3 -> L4 plus CLI and 5-Gate OSS hygiene.
All sensitive or forbidden patterns are synthesized dynamically at runtime.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

_SAMPLE_CYRILLIC = "".join(chr(c) for c in (1055, 1088, 1080, 1074, 1077, 1090))
_SAMPLE_COOKIE_1PSID = "__Secure-" + "1PSID=g.a0001234567890abcdef"
_SAMPLE_GITHUB_PAT = "gh" + "o_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
_SAMPLE_GOOGLE_API_KEY = "AI" + "za" + "SyD1234567890abcdefghijklmnopqrstuv"
_DYNAMIC_PII_TOKEN = "Ora" + "kul"
_FORBIDDEN_REPO_TOKENS = (
    "Ora" + "kul " + "Grey",
    "Ora" + "kul",
    "kuro" + "ora" + "kul" + "grey",
    "ANTI" + "GRAVITY",
)


# ============================================================================
# REQ-001 — Tier L1: Atomic Primitives (agy_secret_shield.l1_primitives)
# ============================================================================


def test_l1_secret_signature_catalog_completeness() -> None:
    from agy_secret_shield.l1_primitives import SECRET_SIGNATURE_CATALOG

    required_rules = {
        "google_cookie_1psid",
        "google_cookie_sapisid",
        "github_pat",
        "google_api_key",
        "openai_api_key",
        "private_key_pem",
        "personal_user_path",
        "cyrillic_marker",
    }
    assert isinstance(SECRET_SIGNATURE_CATALOG, dict)
    assert len(SECRET_SIGNATURE_CATALOG) >= 8
    assert required_rules.issubset(set(SECRET_SIGNATURE_CATALOG.keys()))
    for rule_id, meta in SECRET_SIGNATURE_CATALOG.items():
        assert isinstance(rule_id, str) and rule_id
        assert "category" in meta and isinstance(meta["category"], str)
        assert "severity_weight" in meta and int(meta["severity_weight"]) > 0
        assert "description" in meta and isinstance(meta["description"], str)


def test_l1_compute_token_entropy_boundaries() -> None:
    from agy_secret_shield.l1_primitives import compute_token_entropy

    assert compute_token_entropy("") == 0.0
    assert compute_token_entropy("A" * 64) == 0.0
    high_entropy_sample = "aB3$xY9!mK2@pL7#qR4%vN8^zW1&cF5*"
    assert compute_token_entropy(high_entropy_sample) > 4.0


def test_l1_dpapi_seal_and_unseal_roundtrip() -> None:
    from agy_secret_shield.l1_primitives import dpapi_seal_secret, dpapi_unseal_secret

    sample_secret = "session-secret-" + "9876543210-abcdef"
    envelope = dpapi_seal_secret(sample_secret, description="unit-test-secret")
    assert envelope["engine"] in ("windows_dpapi", "local_aead_fallback")
    assert isinstance(envelope["ciphertext_b64"], str) and len(envelope["ciphertext_b64"]) > 0
    assert isinstance(envelope["sha256"], str) and len(envelope["sha256"]) == 64
    assert isinstance(envelope["redacted_tag"], str) and envelope["redacted_tag"].startswith(
        "[REDACTED_DPAPI:"
    )

    recovered = dpapi_unseal_secret(envelope)
    assert recovered == sample_secret


def test_l1_dpapi_validation_errors() -> None:
    from agy_secret_shield.l1_primitives import dpapi_seal_secret, dpapi_unseal_secret

    with pytest.raises(ValueError):
        dpapi_seal_secret("")

    with pytest.raises(ValueError):
        dpapi_unseal_secret({"engine": "windows_dpapi", "ciphertext_b64": ""})

    with pytest.raises(ValueError):
        dpapi_unseal_secret({"engine": "windows_dpapi", "ciphertext_b64": "!!!not_valid_base64!!!"})


def test_l1_scan_text_clean_input() -> None:
    from agy_secret_shield.l1_primitives import scan_text_for_secrets

    clean_code = "def compute_sum(a: int, b: int) -> int:\n    return a + b\n"
    result = scan_text_for_secrets(clean_code)
    assert result["clean"] is True
    assert result["finding_count"] == 0
    assert result["risk_score"] == 0
    assert result["findings"] == []
    assert result["sanitized_text"] == clean_code


def test_l1_scan_text_detects_secrets_cyrillic_and_custom_pii() -> None:
    from agy_secret_shield.l1_primitives import scan_text_for_secrets

    contaminated = (
        f"cookie={_SAMPLE_COOKIE_1PSID}\n"
        f"token={_SAMPLE_GITHUB_PAT}\n"
        f"api_key={_SAMPLE_GOOGLE_API_KEY}\n"
        f"greeting={_SAMPLE_CYRILLIC}\n"
        f"owner={_DYNAMIC_PII_TOKEN}\n"
    )
    result = scan_text_for_secrets(contaminated, extra_pii_tokens=[_DYNAMIC_PII_TOKEN])
    assert result["clean"] is False
    assert result["finding_count"] >= 4
    assert result["risk_score"] > 0
    assert len(result["findings"]) >= 4
    assert "[REDACTED_DPAPI:" in result["sanitized_text"]
    assert _SAMPLE_COOKIE_1PSID not in result["sanitized_text"]
    assert _SAMPLE_GITHUB_PAT not in result["sanitized_text"]


# ============================================================================
# REQ-002 — Tier L2: Native Plugin Bundle (plugins/agy-secret-shield/)
# ============================================================================


def test_l2_plugin_manifest_schema_and_files() -> None:
    plugin_root = REPO_ROOT / "plugins" / "agy-secret-shield"
    manifest_path = plugin_root / "plugin.json"
    assert manifest_path.is_file()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    allowed_keys = {"name", "displayName", "description", "version", "logo", "suggestedPrompts"}
    assert set(manifest.keys()).issubset(allowed_keys)
    assert manifest["name"] == "agy-secret-shield"
    assert (plugin_root / "assets" / "logo.svg").is_file()
    assert (plugin_root / "skills" / "secret-shield" / "SKILL.md").is_file()
    assert (plugin_root / "agents" / "agy-secret-shield-agent.md").is_file()


def test_l2_plugin_hooks_mcp_and_rules_compliance() -> None:
    plugin_root = REPO_ROOT / "plugins" / "agy-secret-shield"
    hooks_path = plugin_root / "hooks.json"
    mcp_path = plugin_root / "mcp_config.json"
    rules_path = plugin_root / "rules" / "AGENTS.md"

    assert hooks_path.is_file()
    hooks_data = json.loads(hooks_path.read_text(encoding="utf-8"))
    assert hooks_data.get("consolidated_into") == "agy-golden-stack"

    assert mcp_path.is_file()
    mcp_data = json.loads(mcp_path.read_text(encoding="utf-8"))
    servers = mcp_data.get("mcpServers", {})
    assert len(servers) >= 1
    for server_key, server_cfg in servers.items():
        assert server_key.startswith("agy-secret-shield")
        assert len(server_key) < 64
        for tool_name in server_cfg.get("tools", []):
            assert len(tool_name) < 64

    assert rules_path.is_file()
    rules_text = rules_path.read_text(encoding="utf-8")
    assert not rules_text.lstrip().startswith("---")


# ============================================================================
# REQ-003 — Tier L3: 5-Stage Secret & Privacy Audit Pipeline
# ============================================================================


def test_l3_pipeline_clean_repo_profile() -> None:
    from agy_secret_shield.l3_pipeline import SecretShieldPipeline

    pipeline = SecretShieldPipeline()
    report = pipeline.audit_target(profile="clean_repo")
    expected_stages = [
        "STAGE_1_SIGNATURE_AND_PII_SCAN",
        "STAGE_2_SHANNON_ENTROPY_ANALYSIS",
        "STAGE_3_GIT_HISTORY_AND_INDEX_AUDIT",
        "STAGE_4_DPAPI_QUARANTINE_REDACTION",
        "STAGE_5_CRYPTO_CLEAN_CERTIFICATE",
    ]
    assert report["ok"] is True
    assert report["clean"] is True
    assert report["finding_count"] == 0
    assert report["risk_score"] == 0
    assert report["severity"] == "CLEAN"
    assert [s["stage"] for s in report["stages"]] == expected_stages
    assert isinstance(report["certificate_sha256"], str) and len(report["certificate_sha256"]) == 64


def test_l3_pipeline_leaked_cookies_and_pii_profiles() -> None:
    from agy_secret_shield.l3_pipeline import SecretShieldPipeline

    pipeline = SecretShieldPipeline()
    for profile_name in ("leaked_cookies", "pii_contaminant"):
        report = pipeline.audit_target(profile=profile_name)
        assert report["ok"] is True
        assert report["clean"] is False
        assert report["finding_count"] >= 1
        assert report["risk_score"] >= 60
        assert report["severity"] in ("HIGH", "CRITICAL")
        assert isinstance(report["dpapi_quarantine"], list) and len(report["dpapi_quarantine"]) >= 1
        assert "[REDACTED_DPAPI:" in report["sanitized_preview"]


def test_l3_pipeline_invalid_profile_raises() -> None:
    from agy_secret_shield.l3_pipeline import SecretShieldPipeline

    pipeline = SecretShieldPipeline()
    with pytest.raises(ValueError):
        pipeline.audit_target(profile="non_existent_profile_xyz")


# ============================================================================
# REQ-004 — Tier L4: FastAPI Workstation & Cross-L4 Root Telemetry
# ============================================================================


def test_l4_workstation_html_testids() -> None:
    from agy_secret_shield.l4_app import app

    client = TestClient(app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    html = resp.text
    for testid in (
        'data-testid="shield-l4-workstation"',
        'data-testid="shield-profile-select"',
        'data-testid="shield-dpapi-badge"',
        'data-testid="shield-audit-btn"',
        'data-testid="shield-report-root-btn"',
    ):
        assert testid in html


def test_l4_catalog_endpoint() -> None:
    from agy_secret_shield.l4_app import app

    client = TestClient(app)
    resp = client.get("/api/shield/catalog")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["rule_count"] >= 8
    assert isinstance(payload["rules"], dict)
    assert payload["profiles"] == ["clean_repo", "leaked_cookies", "pii_contaminant"]
    assert isinstance(payload["dpapi_available"], bool)


def test_l4_audit_endpoint_profiles_and_error_handling() -> None:
    from agy_secret_shield.l4_app import app

    client = TestClient(app)
    clean_resp = client.post("/api/shield/audit", json={"profile": "clean_repo"})
    assert clean_resp.status_code == 200
    assert clean_resp.json()["clean"] is True

    leak_resp = client.post("/api/shield/audit", json={"profile": "leaked_cookies"})
    assert leak_resp.status_code == 200
    assert leak_resp.json()["clean"] is False

    pii_resp = client.post("/api/shield/audit", json={"profile": "pii_contaminant"})
    assert pii_resp.status_code == 200
    assert pii_resp.json()["clean"] is False

    bad_resp = client.post("/api/shield/audit", json={"profile": "unknown_bad_profile"})
    assert bad_resp.status_code == 400


def test_l4_dpapi_seal_endpoint() -> None:
    from agy_secret_shield.l4_app import app

    client = TestClient(app)
    secret_val = "live-vault-secret-" + "424242"
    resp = client.post(
        "/api/shield/dpapi-seal",
        json={"plaintext": secret_val, "description": "l4-endpoint-test"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["roundtrip_verified"] is True
    assert data["envelope"]["redacted_tag"].startswith("[REDACTED_DPAPI:")

    empty_resp = client.post("/api/shield/dpapi-seal", json={"plaintext": ""})
    assert empty_resp.status_code == 400


def test_l4_report_to_root_endpoint(tmp_path: Path) -> None:
    from agy_secret_shield.l4_app import app

    client = TestClient(app)
    resp = client.post(
        "/api/shield/report-to-root",
        json={"profile": "clean_repo", "target_root_dir": str(tmp_path)},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True

    jsonl_file = tmp_path / "child_session_reports.jsonl"
    md_file = tmp_path / "SECRET_SHIELD_HANDOFF_REPORT.md"
    assert jsonl_file.is_file()
    assert md_file.is_file()
    lines = [line for line in jsonl_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) >= 1
    record = json.loads(lines[-1])
    assert record["project"] == "agy-secret-shield"


# ============================================================================
# REQ-005 — CLI & 5-Gate OSS Repository Hygiene
# ============================================================================


def test_cli_audit_clean_repo_exit_zero(capsys: pytest.CaptureFixture[str]) -> None:
    from agy_secret_shield import cli

    rc = cli.main(["audit", "--profile", "clean_repo", "--json"])
    assert rc == 0
    captured = capsys.readouterr().out
    parsed = json.loads(captured)
    assert parsed["clean"] is True


def test_oss_hygiene_license_skill_and_zero_contaminants() -> None:
    license_file = REPO_ROOT / "LICENSE"
    skill_file = REPO_ROOT / ".agents" / "skills" / "secret-shield" / "SKILL.md"
    assert license_file.is_file()
    assert "MIT License" in license_file.read_text(encoding="utf-8")
    assert skill_file.is_file()

    excluded_parts = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", ".supergraph"}
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in excluded_parts for part in path.parts):
            continue
        if path.suffix.lower() in {".pyc", ".png", ".jpg", ".exe", ".dll", ".db", ".sqlite"}:
            continue
        content = path.read_text(encoding="utf-8", errors="ignore")
        for ch in content:
            assert not (0x0400 <= ord(ch) <= 0x04FF), f"Cyrillic character found in {path}"
        lower_content = content.lower()
        for token in _FORBIDDEN_REPO_TOKENS:
            assert token.lower() not in lower_content, f"Forbidden token found in {path}"
