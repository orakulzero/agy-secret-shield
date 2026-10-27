"""
ISO 9001:2015 / Agile V Verification Suite for AGY Secret Shield v2.0.0 Features.

REQ-SS-201:
1. Version alignment (2.0.0 across pyproject.toml, plugin.json, and __init__.py).
2. OASIS SARIF 2.1.0 standard JSON schema exporter (export_secret_scan_sarif).
3. Driver metadata, rule definitions, and physicalLocation URI / region coordinates.
4. File output persistence to custom path.
5. Incremental unified git diff parsing with exact target line number tracking across hunks.
6. Detection of added credentials in (+) lines (OpenAI key, GitHub PAT, Google API key).
7. Suppression of deleted (-) lines and context ( ) lines.
8. False-positive filtering for test/mock variables and SHA-256 hex constants.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any, Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import agy_secret_shield
from agy_secret_shield import export_secret_scan_sarif, scan_git_diff_incremental


# ============================================================================
# Test 1: Version Alignment
# ============================================================================
def test_v2_0_version_alignment() -> None:
    assert agy_secret_shield.__version__ == "2.0.0"

    pyproject_text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "2.0.0"' in pyproject_text

    plugin_json_path = REPO_ROOT / "plugins" / "agy-secret-shield" / "plugin.json"
    assert plugin_json_path.is_file()
    plugin_data = json.loads(plugin_json_path.read_text(encoding="utf-8"))
    assert plugin_data.get("version") == "2.0.0"


# ============================================================================
# Test 2: OASIS SARIF 2.1.0 Schema Compliance
# ============================================================================
def test_v2_0_export_sarif_schema_compliance() -> None:
    findings = [
        {
            "rule_id": "openai_api_key",
            "file_path": "src/llm/client.py",
            "line_number": 42,
            "col_offset": 12,
            "sample": "sk-test12345678901234567890",
            "category": "cloud_credential",
            "severity_weight": 45,
            "description": "OpenAI API Key",
        }
    ]

    sarif = export_secret_scan_sarif({"findings": findings})
    assert sarif["version"] == "2.1.0"
    assert "https://docs.oasis-open.org/sarif" in sarif["$schema"]
    assert len(sarif["runs"]) == 1

    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "AGY Secret Shield"
    assert driver["version"] == "2.0.0"
    assert driver["semanticVersion"] == "2.0.0"
    assert len(driver["rules"]) >= 10


# ============================================================================
# Test 3: SARIF Rule Definitions and Location Coordinates
# ============================================================================
def test_v2_0_export_sarif_rule_definitions_and_locations() -> None:
    findings = [
        {
            "rule_id": "github_pat",
            "file_path": "config/git.py",
            "line_number": 15,
            "start_column": 8,
            "sample": "ghp_xxxxxxxxxxxxxxxxxxxx",
            "severity": "error",
            "category": "scm_token",
        }
    ]

    sarif = export_secret_scan_sarif({"findings": findings})
    results = sarif["runs"][0]["results"]
    assert len(results) == 1

    r0 = results[0]
    assert r0["ruleId"] == "github_pat"
    assert r0["level"] == "error"

    loc = r0["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "config/git.py"
    assert loc["region"]["startLine"] == 15
    assert loc["region"]["startColumn"] == 8


# ============================================================================
# Test 4: SARIF File Output Persistence
# ============================================================================
def test_v2_0_export_sarif_file_output(tmp_path: Path) -> None:
    out_file = tmp_path / "reports" / "security_scan.sarif"
    findings = [
        {
            "rule_id": "google_api_key",
            "file_path": "services/gemini.py",
            "line_number": 28,
            "sample": "AIzaSyDxxxxxxxxxxxxxxxxx",
        }
    ]

    res = export_secret_scan_sarif(findings, output_path=out_file)
    assert out_file.is_file()

    saved_data = json.loads(out_file.read_text(encoding="utf-8"))
    assert saved_data["version"] == "2.1.0"
    assert len(saved_data["runs"][0]["results"]) == 1
    assert saved_data == res


# ============================================================================
# Test 5: Incremental Unified Diff Line Number Tracking Across Hunks
# ============================================================================
def test_v2_0_diff_incremental_line_number_tracking() -> None:
    diff_text = """diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -10,3 +15,6 @@ def init_app():
 context_line_1
 context_line_2
+line_15_added = True
+line_16_added = False
+api_key = "sk-live1234567890123456789012"
 context_line_3
@@ -50,2 +55,4 @@ def helper():
 context_a
+other_var = 99
+github_token = "ghp_abcdefghijklmnopqrstuvwxyz12"
"""
    res = scan_git_diff_incremental(diff_text)
    assert res["clean"] is False
    assert res["findings_count"] == 2

    f0 = res["findings"][0]
    assert f0["file_path"] == "src/app.py"
    # Hunk 1 starts at line 15, context_1 (15), context_2 (16), line_15_added (17), line_16_added (18), api_key (19)
    assert f0["line_number"] == 19
    assert f0["rule_id"] == "openai_api_key"

    f1 = res["findings"][1]
    # Hunk 2 starts at line 55, context_a (55), other_var (56), github_token (57)
    assert f1["line_number"] == 57
    assert f1["rule_id"] == "github_pat"


# ============================================================================
# Test 6: Secret Detection in Added Lines (Multi-file diff)
# ============================================================================
def test_v2_0_diff_incremental_secret_detection() -> None:
    diff_text = """diff --git a/backend/auth.py b/backend/auth.py
--- a/backend/auth.py
+++ b/backend/auth.py
@@ -1,3 +1,4 @@
 import os
+GOOGLE_API_KEY = "AIzaSyD1234567890abcdef1234567890"
 def login():
diff --git a/frontend/config.js b/frontend/config.js
--- a/frontend/config.js
+++ b/frontend/config.js
@@ -10,2 +10,3 @@ export const API_URL = "/api";
+export const SECRET = "ghp_123456789012345678901234";
"""
    res = scan_git_diff_incremental(diff_text)
    assert res["clean"] is False
    assert res["findings_count"] == 2
    assert "backend/auth.py" in res["scanned_files"]
    assert "frontend/config.js" in res["scanned_files"]

    rule_ids = {f["rule_id"] for f in res["findings"]}
    assert "google_api_key" in rule_ids
    assert "github_pat" in rule_ids


# ============================================================================
# Test 7: Suppression of Deleted (-) and Unchanged Context ( ) Lines
# ============================================================================
def test_v2_0_diff_incremental_ignores_deleted_and_unchanged_lines() -> None:
    diff_text = """diff --git a/old_module.py b/old_module.py
--- a/old_module.py
+++ b/old_module.py
@@ -1,5 +1,4 @@
-OLD_SECRET = "sk-deleted12345678901234567890"
-OLD_PAT = "ghp_deleted12345678901234567890"
 UNCHANGED_LINE = "nothing_to_see_here"
+SAFE_NEW_LINE = "clean_constant"
"""
    res = scan_git_diff_incremental(diff_text)
    assert res["clean"] is True
    assert res["findings_count"] == 0
    assert len(res["findings"]) == 0


# ============================================================================
# Test 8: False-Positive Filtering (Mocks, Fixtures, Commit Hashes)
# ============================================================================
def test_v2_0_diff_incremental_false_positive_avoidance() -> None:
    diff_text = """diff --git a/tests/test_auth.py b/tests/test_auth.py
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -1,4 +1,8 @@
 def test_dummy():
+    mock_api_key = "dummy_mock_secret_key"
+    test_token = "placeholder_token_value"
+    sample_password = "fake_password_123"
+    commit_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
"""
    res = scan_git_diff_incremental(diff_text)
    assert res["clean"] is True
    assert res["findings_count"] == 0
