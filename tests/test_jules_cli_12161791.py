"""ISO 9001 / Agile V P30 pytest module for validate_audit_args path traversal rejection."""

from __future__ import annotations

import pytest
from pathlib import Path

from agy_secret_shield.cli import validate_audit_args


class TestValidateAuditArgsTraversalRejection:
    """Test suite verifying validate_audit_args rejects path traversal attempts."""

    @pytest.mark.parametrize("malicious_path", [
        "../../etc/passwd",
        "../../../etc/shadow",
        "..\\..\\Windows\\System32",
        "..\\..\\Windows\\System32\\cmd.exe",
        "..\\..\\",
        "../../",
        "../relative/path",
        "legitimate/../../sneaky",
        "..\\..\\..\\Windows\\System32\\config\\SAM",
    ])
    def test_reject_paths_containing_dotdot(self, malicious_path: str) -> None:
        """Verify paths containing '..' are rejected with appropriate error."""
        result = validate_audit_args(
            profile="clean_repo",
            repo_path=malicious_path,
            ignore_tests=False
        )
        
        assert result["valid"] is False
        assert len(result["errors"]) == 1
        assert "Path traversal attempt detected" in result["errors"][0]
        assert "repo_path" in result["errors"][0]
        assert "normalized_repo_path" not in result

    def test_accept_legitimate_path_without_dotdot(self) -> None:
        """Verify legitimate paths without '..' are accepted and normalized."""
        result = validate_audit_args(
            profile="strict_audit",
            repo_path="src/agy_secret_shield",
            ignore_tests=True
        )
        
        assert result["valid"] is True
        assert result["errors"] == []
        assert "normalized_repo_path" in result
        assert Path(result["normalized_repo_path"]).is_absolute()

    def test_none_repo_path_is_valid(self) -> None:
        """Verify None repo_path is accepted without normalization."""
        result = validate_audit_args(
            profile="default",
            repo_path=None,
            ignore_tests=False
        )
        
        assert result["valid"] is True
        assert result["errors"] == []
        assert "normalized_repo_path" not in result
        assert result["profile"] == "default"
