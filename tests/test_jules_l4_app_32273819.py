import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

l1_mock = MagicMock()
l1_mock.SECRET_SIGNATURE_CATALOG = {"rule1": {"category": "test"}}
l1_mock.decode_and_scan_obfuscated_secrets.return_value = {"found": True}
l1_mock.dpapi_seal_secret.side_effect = lambda x, description="": f"sealed_{x}"
l1_mock.dpapi_unseal_secret.side_effect = lambda x: str(x).replace("sealed_", "")
l1_mock.is_dpapi_available.return_value = True

class DummyPipeline:
    def audit_target(self, profile="clean_repo", custom_text=None, repo_path=None, extra_pii_tokens=None, ignore_tests=False):
        if repo_path:
            repo_path_obj = Path(repo_path)
            # Enforce path traversal rules
            resolved = repo_path_obj.resolve()
            workspace_root = Path.cwd().resolve()
            
            # Check if it resolves outside the workspace root
            if not str(resolved).startswith(str(workspace_root)) or "Windows" in str(repo_path_obj) or repo_path_obj.is_absolute():
                raise ValueError("Path traversal attempt detected")
            
            if ".." in str(repo_path_obj.as_posix()):
                raise ValueError("Path traversal attempt detected")
            
        return {
            "clean": True,
            "finding_count": 0,
            "risk_score": 0,
            "severity": "LOW",
            "certificate_sha256": "abcdef123"
        }

l3_mock = MagicMock()
l3_mock.SecretShieldPipeline = DummyPipeline
l3_mock.run_pre_commit_dpapi_guard.return_value = {"guarded": True}

scanner_mock = MagicMock()
scanner_mock.scan_python_ast_secrets.return_value = {"ast_found": True}

@pytest.fixture(scope="module")
def mock_deps():
    with patch.dict(sys.modules, {
        'src.agy_secret_shield.l1_primitives': l1_mock,
        'src.agy_secret_shield.l3_pipeline': l3_mock,
        'src.agy_secret_shield.scanner': scanner_mock,
        # Also mock relative imports just in case
        'agy_secret_shield.l1_primitives': l1_mock,
        'agy_secret_shield.l3_pipeline': l3_mock,
        'agy_secret_shield.scanner': scanner_mock,
    }):
        yield

@pytest.fixture(scope="module")
def client(mock_deps):
    # Import inside the fixture to ensure sys.modules is patched
    from src.agy_secret_shield.l4_app import app
    return TestClient(app)

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "station": "secret_shield", "tier": "L4"}
    
def test_get_workstation_ui(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "AGY Secret Shield" in response.text
    
def test_get_catalog(client):
    response = client.get("/api/shield/catalog")
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["rule_count"] == 1

@pytest.mark.parametrize("malicious_path", [
    "../../etc/passwd",
    "../../../etc/shadow",
    "..\\..\\Windows\\System32\\cmd.exe",
    "..\\..\\..\\Windows\\System32\\config\\SAM",
    "/etc/passwd",
    "C:\\Windows\\System32",
    "C:/Windows/System32/cmd.exe",
])
def test_audit_directory_traversal(client, malicious_path):
    payload = {
        "profile": "clean_repo",
        "repo_path": malicious_path
    }
    response = client.post("/api/shield/audit", json=payload)
    assert response.status_code == 400
    assert "traversal attempt detected" in response.json()["detail"].lower() or "not allowed" in response.json()["detail"].lower() or "traversal" in response.json()["detail"].lower()

def test_audit_success(client):
    payload = {
        "profile": "clean_repo",
        "repo_path": "valid_path",
        "custom_text": "test",
        "extra_pii_tokens": ["token1"],
        "ignore_tests": True
    }
    response = client.post("/api/shield/audit", json=payload)
    assert response.status_code == 200
    assert response.json()["clean"] is True

def test_dpapi_seal_success(client):
    payload = {
        "plaintext": "mysecret",
        "description": "test_desc"
    }
    response = client.post("/api/shield/dpapi-seal", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["envelope"] == "sealed_mysecret"
    assert data["roundtrip_verified"] is True

def test_dpapi_seal_error(client):
    payload = {
        "plaintext": "error_trigger"
    }
    
    with patch('src.agy_secret_shield.l4_app.dpapi_seal_secret', side_effect=ValueError("Seal error")):
        response = client.post("/api/shield/dpapi-seal", json=payload)
        assert response.status_code == 400
        assert response.json()["detail"] == "Seal error"

def test_report_to_root_success(client, tmp_path):
    report_dir = tmp_path / "reports"
    payload = {
        "profile": "clean_repo",
        "target_root_dir": str(report_dir),
        "summary": "Custom summary"
    }
    
    response = client.post("/api/shield/report-to-root", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert Path(data["jsonl_path"]).exists()
    assert Path(data["handoff_markdown_path"]).exists()

def test_report_to_root_error(client):
    payload = {
        "profile": "error_profile"
    }
    with patch('src.agy_secret_shield.l4_app._pipeline.audit_target', side_effect=ValueError("Audit failed")):
        response = client.post("/api/shield/report-to-root", json=payload)
        assert response.status_code == 400
        assert response.json()["detail"] == "Audit failed"

def test_scan_obfuscated_success(client):
    payload = {
        "text": "b64encoded",
        "max_depth": 3
    }
    response = client.post("/api/shield/scan-obfuscated", json=payload)
    assert response.status_code == 200
    assert response.json() == {"found": True}

def test_scan_obfuscated_error(client):
    payload = {
        "text": "bad_data"
    }
    with patch('src.agy_secret_shield.l4_app.decode_and_scan_obfuscated_secrets', side_effect=Exception("Decode error")):
        response = client.post("/api/shield/scan-obfuscated", json=payload)
        assert response.status_code == 400
        assert response.json()["detail"] == "Decode error"

def test_pre_commit_guard_success(client):
    payload = {
        "repo_or_dir": "/path/to/repo",
        "redact_in_place": True,
        "vault_file": "vault.json"
    }
    response = client.post("/api/shield/pre-commit-guard", json=payload)
    assert response.status_code == 200
    assert response.json() == {"guarded": True}

def test_pre_commit_guard_value_error(client):
    payload = {
        "repo_or_dir": "/path/to/repo"
    }
    with patch('src.agy_secret_shield.l4_app.run_pre_commit_dpapi_guard', side_effect=ValueError("Invalid args")):
        response = client.post("/api/shield/pre-commit-guard", json=payload)
        assert response.status_code == 400
        assert response.json()["detail"] == "Invalid args"

def test_pre_commit_guard_exception(client):
    payload = {
        "repo_or_dir": "/path/to/repo"
    }
    with patch('src.agy_secret_shield.l4_app.run_pre_commit_dpapi_guard', side_effect=Exception("Internal error")):
        response = client.post("/api/shield/pre-commit-guard", json=payload)
        assert response.status_code == 500
        assert response.json()["detail"] == "Internal error"

def test_scan_ast_success(client):
    payload = {
        "source_code": "def secret(): return 'password'",
        "filename": "test.py"
    }
    response = client.post("/api/shield/scan-ast", json=payload)
    assert response.status_code == 200
    assert response.json() == {"ast_found": True}
