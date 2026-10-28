"""Agile V Real Integration Test Suite: Path Traversal Hardening on POST /api/shield/audit.

Repository: agy-secret-shield | Target: src/agy_secret_shield/l4_app.py
Traceability: REQ-SS-203 (Hardened path traversal boundary protection on real app).
Constraints: Real integration tests without mocking l1_primitives or l3_pipeline.
"""

from __future__ import annotations
from pathlib import Path
import sys
import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from agy_secret_shield.l4_app import app


@pytest.fixture(scope="module")
def unmocked_client() -> TestClient:
    """Real FastAPI TestClient without mocking l1_primitives or l3_pipeline."""
    return TestClient(app)


TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/shadow",
    "..\\..\\Windows\\System32",
    "..\\..\\Windows\\System32\\cmd.exe",
    "..\\..\\",
    "../../",
    "C:\\Windows\\System32",
    "C:/Windows/System32",
    "/etc/passwd",
    "/etc/shadow",
    "..\\..\\..\\Windows\\System32\\config\\SAM",
]


@pytest.mark.timeout(3)
@pytest.mark.parametrize("payload", TRAVERSAL_PAYLOADS)
def test_audit_endpoint_rejects_path_traversal(
    unmocked_client: TestClient, payload: str
) -> None:
    """Verifies that malicious directory traversal payloads return HTTP 400 with exact detail."""
    response = unmocked_client.post(
        "/api/shield/audit",
        json={"profile": "clean_repo", "repo_path": payload},
    )
    assert response.status_code == 400
    detail = response.json().get("detail", "")
    assert "Path traversal attempt detected" in detail


@pytest.mark.timeout(3)
@pytest.mark.parametrize("payload", [
    "....//....//etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    ".\\..\\..\\",
])
def test_audit_endpoint_rejects_evasion_traversal(
    unmocked_client: TestClient, payload: str
) -> None:
    """Verifies that encoded and nested directory traversal payloads are rejected."""
    response = unmocked_client.post(
        "/api/shield/audit",
        json={"profile": "clean_repo", "repo_path": payload},
    )
    assert response.status_code == 400
    detail = response.json().get("detail", "")
    assert "Path traversal attempt detected" in detail


def test_audit_endpoint_allows_omitted_repo_path(
    unmocked_client: TestClient,
) -> None:
    """Verifies that default profile audits without repo_path succeed with HTTP 200."""
    response = unmocked_client.post(
        "/api/shield/audit",
        json={"profile": "clean_repo"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data.get("clean") is True
    assert data.get("finding_count") == 0


def test_audit_endpoint_allows_legitimate_workspace_path(
    unmocked_client: TestClient, tmp_path: Path
) -> None:
    """Verifies that legitimate paths do not trigger traversal errors."""
    valid_file = tmp_path / "valid_code.py"
    valid_file.write_text("x = 100\n", encoding="utf-8")
    response = unmocked_client.post(
        "/api/shield/audit",
        json={"profile": "clean_repo", "repo_path": str(tmp_path)},
    )
    # Must not be flagged as a path traversal attempt
    if response.status_code == 400:
        detail = response.json().get("detail", "")
        assert "Path traversal attempt detected" not in detail
