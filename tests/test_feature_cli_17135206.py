"""Test suite for validate_audit_args helper in cli.py"""

from __future__ import annotations
import pytest
from pathlib import Path
from agy_secret_shield.cli import validate_audit_args


def test_validate_audit_args_accepts_valid_profile():
    """Assert that standard profile names pass validation."""
    result = validate_audit_args(
        profile="clean_repo",
        repo_path=None,
        ignore_tests=False
    )
    assert result["valid"] is True
    assert result["profile"] == "clean_repo"
    assert "errors" not in result or len(result["errors"]) == 0


def test_validate_audit_args_rejects_path_traversal():
    """Assert that path traversal attempts are detected and rejected."""
    result = validate_audit_args(
        profile="clean_repo",
        repo_path="../../etc/passwd",
        ignore_tests=False
    )
    assert result["valid"] is False
    assert any("traversal" in err.lower() for err in result["errors"])


def test_validate_audit_args_normalizes_relative_paths():
    """Assert that safe relative paths are resolved to absolute canonical form."""
    result = validate_audit_args(
        profile="strict_scan",
        repo_path="./subdir/project",
        ignore_tests=True
    )
    assert result["valid"] is True
    assert "normalized_repo_path" in result
    normalized = result["normalized_repo_path"]
    assert normalized is not None
    assert Path(normalized).is_absolute()
