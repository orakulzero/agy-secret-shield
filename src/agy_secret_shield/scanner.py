"""AST-Aware Semantic Secret & Taint Analyzer for Python Source Code.

Identifies live credentials, annotated assignments, API client call arguments,
environment variable fallbacks, and concatenated taint flows while suppressing
benign test assertions, docstrings, mock variables, and cryptographic hex constants.
"""

from __future__ import annotations

import ast
import re
from typing import Any, Dict, List, Optional, Set, Tuple

_SENSITIVE_VAR_NAMES = {
    "api_key",
    "apikey",
    "secret",
    "secret_key",
    "aws_secret_access_key",
    "token",
    "access_token",
    "auth_token",
    "password",
    "passwd",
    "private_key",
    "client_secret",
    "db_password",
    "session_token",
    "authorization",
}

_BENIGN_VAR_PREFIXES = (
    "mock_",
    "dummy_",
    "test_",
    "sample_",
    "example_",
    "fake_",
    "placeholder_",
    "fixture_",
    "expected_",
    "stub_",
)

# Regex patterns for credential formats
_OPENAI_KEY_RE = re.compile(r"^sk-[A-Za-z0-9\-_]{20,}$")
_GOOGLE_KEY_RE = re.compile(r"^AIza[0-9A-Za-z\-_]{20,}$")
_GITHUB_PAT_RE = re.compile(
    r"^(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}$|^github_pat_[A-Za-z0-9_]{22,}$"
)
_JWT_TOKEN_RE = re.compile(
    r"^ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$"
)
_HEX_CONSTANT_RE = re.compile(
    r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$"
)
_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)


def _is_hex_constant(val: str) -> bool:
    """Check if value is a 32, 40, or 64 character hex constant (e.g. SHA-256, MD5)."""
    return bool(_HEX_CONSTANT_RE.match(val.strip()))


def _is_benign_variable_name(name: str) -> bool:
    """Check if variable name indicates a mock, test fixture, or dummy placeholder."""
    lower = name.lower()
    return any(
        lower.startswith(prefix)
        or lower.endswith("_dummy")
        or lower.endswith("_mock")
        for prefix in _BENIGN_VAR_PREFIXES
    )


def _match_credential_signature(val: str) -> Optional[str]:
    """Match string literal against known credential signatures."""
    val_clean = val.strip()
    if _OPENAI_KEY_RE.match(val_clean):
        return "openai_api_key"
    if _GOOGLE_KEY_RE.match(val_clean):
        return "google_api_key"
    if _GITHUB_PAT_RE.match(val_clean):
        return "github_pat"
    if _JWT_TOKEN_RE.match(val_clean):
        return "jwt_token"
    if _PEM_PRIVATE_KEY_RE.search(val_clean):
        return "private_key_pem"
    # Generic high-entropy credential pattern
    if (
        len(val_clean) >= 24
        and any(c.isupper() for c in val_clean)
        and any(c.islower() for c in val_clean)
        and any(c.isdigit() for c in val_clean)
    ):
        return "generic_high_entropy_secret"
    return None


def _evaluate_static_ast_string(node: ast.AST) -> Optional[Tuple[str, List[str]]]:
    """Recursively evaluate string constants and string concatenations (+).

    Returns:
        (concatenated_string, list_of_parts) if evaluatable, else None.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, [node.value]

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left_res = _evaluate_static_ast_string(node.left)
        right_res = _evaluate_static_ast_string(node.right)
        if left_res is not None and right_res is not None:
            return left_res[0] + right_res[0], left_res[1] + right_res[1]

    if isinstance(node, ast.JoinedStr):
        # f-string: extract constant segments
        parts: List[str] = []
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                parts.append(val.value)
        if parts:
            return "".join(parts), parts

    return None


class _ASTSecretScannerVisitor(ast.NodeVisitor):
    """AST visitor tracking live credential assignments, client call args,

    environment fallbacks, and taint concatenation while filtering test assertions,
    docstrings, mock variables, and cryptographic hex constants.
    """

    def __init__(self, source_code: str) -> None:
        self.source_code = source_code
        self.findings: List[Dict[str, Any]] = []
        self.false_positive_filters: List[Dict[str, Any]] = []
        self.taint_flows: List[Dict[str, Any]] = []
        self.assertion_lines: Set[int] = set()
        self.docstring_lines: Set[int] = set()

    def visit_Assert(self, node: ast.Assert) -> Any:
        """Mark assertion line as benign test context and filter contained secrets."""
        self.assertion_lines.add(node.lineno)
        # Scan for string comparisons inside the assertion to register as filtered
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                rule = _match_credential_signature(child.value)
                if rule or _is_hex_constant(child.value) or len(child.value) >= 20:
                    self.false_positive_filters.append({
                        "reason": "test_assertion",
                        "line_number": node.lineno,
                        "snippet": f"assert ... '{child.value[:16]}...'",
                    })
        # Do not recurse into child nodes to prevent false alarms
        return

    def visit_Expr(self, node: ast.Expr) -> Any:
        """Identify standalone string docstrings."""
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            self.docstring_lines.add(node.lineno)
            self.false_positive_filters.append({
                "reason": "docstring",
                "line_number": node.lineno,
                "snippet": f"Docstring: '{node.value.value[:30]}...'",
            })
            return
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        """Analyze variable assignments for credentials and taint flows."""
        if node.lineno in self.assertion_lines or node.lineno in self.docstring_lines:
            return

        # Extract target variable names
        targets: List[str] = []
        for t in node.targets:
            if isinstance(t, ast.Name):
                targets.append(t.id)
            elif isinstance(t, ast.Attribute):
                targets.append(t.attr)

        eval_res = _evaluate_static_ast_string(node.value)
        if eval_res is not None:
            full_val, parts = eval_res
            for var_name in targets:
                lower_var = var_name.lower()

                # 1. Benign mock variable filter
                if _is_benign_variable_name(var_name):
                    self.false_positive_filters.append({
                        "reason": "mock_variable",
                        "variable": var_name,
                        "line_number": node.lineno,
                        "snippet": f"{var_name} = '...'",
                    })
                    continue

                # 2. Cryptographic hex constant filter (SHA-256, MD5)
                if _is_hex_constant(full_val):
                    self.false_positive_filters.append({
                        "reason": "hex_constant",
                        "variable": var_name,
                        "line_number": node.lineno,
                        "snippet": f"{var_name} = '{full_val[:16]}...'",
                    })
                    continue

                # 3. Concatenated / split secret taint tracking
                rule = _match_credential_signature(full_val)
                is_sensitive_var = any(s in lower_var for s in _SENSITIVE_VAR_NAMES)

                if len(parts) > 1 and (rule or is_sensitive_var):
                    self.taint_flows.append({
                        "variable": var_name,
                        "line_number": node.lineno,
                        "parts": parts,
                        "reconstructed": full_val,
                        "rule_id": rule or "concatenated_secret",
                    })
                    self.findings.append({
                        "category": "taint_concatenation",
                        "variable_or_arg": var_name,
                        "line_number": node.lineno,
                        "rule_id": rule or "concatenated_secret",
                        "confidence": "HIGH",
                        "parts_count": len(parts),
                    })
                    continue

                # 4. Live credential assignment
                if rule or (is_sensitive_var and len(full_val) >= 16):
                    self.findings.append({
                        "category": "live_assignment",
                        "variable_or_arg": var_name,
                        "line_number": node.lineno,
                        "rule_id": rule or "sensitive_variable_assignment",
                        "confidence": "HIGH",
                        "snippet": f"{var_name} = '...'",
                    })

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        """Analyze annotated assignments (e.g. api_key: str = '...')."""
        if node.lineno in self.assertion_lines or node.lineno in self.docstring_lines:
            return

        if node.value is None:
            return

        var_name = ""
        if isinstance(node.target, ast.Name):
            var_name = node.target.id
        elif isinstance(node.target, ast.Attribute):
            var_name = node.target.attr

        if not var_name:
            return

        eval_res = _evaluate_static_ast_string(node.value)
        if eval_res is not None:
            full_val, parts = eval_res
            lower_var = var_name.lower()

            if _is_benign_variable_name(var_name):
                self.false_positive_filters.append({
                    "reason": "mock_variable",
                    "variable": var_name,
                    "line_number": node.lineno,
                    "snippet": f"{var_name} = '...'",
                })
                return

            if _is_hex_constant(full_val):
                self.false_positive_filters.append({
                    "reason": "hex_constant",
                    "variable": var_name,
                    "line_number": node.lineno,
                    "snippet": f"{var_name} = '{full_val[:16]}...'",
                })
                return

            rule = _match_credential_signature(full_val)
            is_sensitive_var = any(s in lower_var for s in _SENSITIVE_VAR_NAMES)

            if len(parts) > 1 and (rule or is_sensitive_var):
                self.taint_flows.append({
                    "variable": var_name,
                    "line_number": node.lineno,
                    "parts": parts,
                    "reconstructed": full_val,
                    "rule_id": rule or "concatenated_secret",
                })
                self.findings.append({
                    "category": "taint_concatenation",
                    "variable_or_arg": var_name,
                    "line_number": node.lineno,
                    "rule_id": rule or "concatenated_secret",
                    "confidence": "HIGH",
                    "parts_count": len(parts),
                })
                return

            if rule or (is_sensitive_var and len(full_val) >= 16):
                self.findings.append({
                    "category": "live_assignment",
                    "variable_or_arg": var_name,
                    "line_number": node.lineno,
                    "rule_id": rule or "sensitive_variable_assignment",
                    "confidence": "HIGH",
                    "snippet": f"{var_name} = '...'",
                })

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        """Analyze function invocations for API client credentials and os.getenv fallbacks."""
        if node.lineno in self.assertion_lines or node.lineno in self.docstring_lines:
            return

        # 1. os.getenv("KEY", "fallback_secret") or os.environ.get("KEY", "fallback_secret")
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in ("getenv", "get") and len(node.args) >= 2:
            key_name = ""
            if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                key_name = node.args[0].value

            eval_fallback = _evaluate_static_ast_string(node.args[1])
            if eval_fallback is not None:
                fallback_val, _ = eval_fallback
                rule = _match_credential_signature(fallback_val)
                lower_key = key_name.lower()
                is_sensitive_env = any(
                    s in lower_key for s in ("secret", "key", "token", "password", "auth")
                )

                if rule or (
                    is_sensitive_env
                    and len(fallback_val) >= 16
                    and not _is_benign_variable_name(fallback_val)
                ):
                    self.findings.append({
                        "category": "env_fallback",
                        "variable_or_arg": key_name or "ENV_VAR",
                        "line_number": node.lineno,
                        "rule_id": rule or "env_fallback_secret",
                        "confidence": "HIGH",
                        "fallback_value": fallback_val,
                    })

        # 2. API client keyword arguments (Client(api_key="..."))
        for kw in node.keywords:
            if kw.arg and any(s in kw.arg.lower() for s in ("api_key", "secret", "token", "auth")):
                eval_kw = _evaluate_static_ast_string(kw.value)
                if eval_kw is not None:
                    kw_val, parts = eval_kw
                    rule = _match_credential_signature(kw_val)
                    if _is_benign_variable_name(kw_val) or _is_hex_constant(kw_val):
                        self.false_positive_filters.append({
                            "reason": "mock_client_argument",
                            "line_number": node.lineno,
                            "snippet": f"{kw.arg} = '...'",
                        })
                    elif rule or len(kw_val) >= 16:
                        self.findings.append({
                            "category": "api_client_arg",
                            "variable_or_arg": kw.arg,
                            "line_number": node.lineno,
                            "rule_id": rule or "api_client_credential_arg",
                            "confidence": "HIGH",
                            "snippet": f"{kw.arg}=...",
                        })

        self.generic_visit(node)


def scan_python_ast_secrets(
    source_code: str,
    filename: str = "<memory>",
) -> Dict[str, Any]:
    """Parse Python code using AST and identify live secrets, client arguments,

    and environment fallbacks while filtering test assertions, docstrings,
    mock variables, and cryptographic hex constants.

    Args:
        source_code: Python source code as string.
        filename: Optional filename label.

    Returns:
        Structured dict with findings, false_positive_filters, and taint_flows.
    """
    if not isinstance(source_code, str):
        return {
            "findings": [],
            "false_positive_filters": [],
            "taint_flows": [],
            "clean": True,
            "error": "source_code must be a string",
        }

    try:
        tree = ast.parse(source_code, filename=filename)
    except SyntaxError as syn_err:
        return {
            "findings": [],
            "false_positive_filters": [],
            "taint_flows": [],
            "clean": True,
            "syntax_error": str(syn_err),
            "line_number": syn_err.lineno,
        }

    visitor = _ASTSecretScannerVisitor(source_code)
    visitor.visit(tree)

    clean = (len(visitor.findings) == 0)

    return {
        "findings": visitor.findings,
        "false_positive_filters": visitor.false_positive_filters,
        "taint_flows": visitor.taint_flows,
        "clean": clean,
        "live_credential_count": len(visitor.findings),
        "benign_skipped_count": len(visitor.false_positive_filters),
        "benign_skipped": visitor.false_positive_filters,  # Schema alias
    }


def export_secret_scan_sarif(
    scan_results: Union[Dict[str, Any], List[Dict[str, Any]]],
    output_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Export secret scan findings conforming to OASIS SARIF 2.1.0 JSON schema.

    Args:
        scan_results: Structured dict or list containing findings from AST, diff, or text scan.
        output_path: Optional file path to persist JSON output.

    Returns:
        Structured SARIF 2.1.0 dict.
    """
    import json
    from pathlib import Path
    from .l1_primitives import SECRET_SIGNATURE_CATALOG

    if isinstance(scan_results, dict):
        findings = scan_results.get("findings", [])
    elif isinstance(scan_results, list):
        findings = scan_results
    else:
        findings = []

    # Build catalog rules and dynamic rules
    sarif_rules: List[Dict[str, Any]] = []
    rule_ids_seen: Set[str] = set()

    for r_id, meta in SECRET_SIGNATURE_CATALOG.items():
        weight = meta.get("severity_weight", 40)
        lvl = "error" if weight >= 40 else ("warning" if weight >= 25 else "note")
        sarif_rules.append({
            "id": r_id,
            "name": r_id,
            "shortDescription": {"text": meta.get("description", r_id)},
            "fullDescription": {"text": f"Rule {r_id} detects {meta.get('category', 'secret')} contaminants."},
            "defaultConfiguration": {"level": lvl},
            "properties": {
                "category": meta.get("category", "secret"),
                "severity_weight": weight,
            },
        })
        rule_ids_seen.add(r_id)

    # Dynamic rules for findings with custom rule_ids
    for f in findings:
        r_id = f.get("rule_id") or f.get("secret_type") or "generic_secret"
        if r_id not in rule_ids_seen:
            weight = f.get("severity_weight") or f.get("severity") or 40
            if isinstance(weight, str):
                weight = 50 if weight.lower() == "error" else 30
            lvl = "error" if weight >= 40 else "warning"
            sarif_rules.append({
                "id": r_id,
                "name": r_id,
                "shortDescription": {"text": f.get("description", f"Detected sensitive pattern: {r_id}")},
                "fullDescription": {"text": f"Automated detection for secret pattern: {r_id}"},
                "defaultConfiguration": {"level": lvl},
                "properties": {
                    "category": f.get("category", "credential"),
                    "severity_weight": weight,
                },
            })
            rule_ids_seen.add(r_id)

    rule_index_map = {r["id"]: idx for idx, r in enumerate(sarif_rules)}

    results: List[Dict[str, Any]] = []
    for f in findings:
        r_id = f.get("rule_id") or f.get("secret_type") or "generic_secret"
        r_idx = rule_index_map.get(r_id, 0)
        rule_def = sarif_rules[r_idx]
        default_lvl = rule_def["defaultConfiguration"]["level"]

        weight = f.get("severity_weight") or f.get("severity")
        if isinstance(weight, int):
            level = "error" if weight >= 40 else "warning"
        elif isinstance(weight, str) and weight.lower() in ("error", "warning", "note"):
            level = weight.lower()
        else:
            level = default_lvl

        file_path = f.get("file_path") or f.get("filename") or "<unknown>"
        line_no = f.get("line_number") or f.get("lineno") or 1
        col_start = f.get("start_column") or f.get("col_offset") or f.get("column") or 1
        col_end = f.get("end_column") or (col_start + len(str(f.get("sample", ""))))

        results.append({
            "ruleId": r_id,
            "ruleIndex": r_idx,
            "level": level,
            "message": {
                "text": f"Detected secret {r_id}: {f.get('description') or f.get('sample') or 'sensitive token'}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": line_no,
                            "startColumn": col_start,
                            "endLine": line_no,
                            "endColumn": max(col_start, col_end),
                        },
                    },
                },
            ],
            "properties": {
                "category": f.get("category", rule_def["properties"]["category"]),
                "sample": f.get("sample", ""),
                "entropy": f.get("entropy", 0.0),
            },
        })

    sarif_doc = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AGY Secret Shield",
                        "version": "2.0.0",
                        "semanticVersion": "2.0.0",
                        "informationUri": "https://github.com/agy-community/agy-secret-shield",
                        "rules": sarif_rules,
                    },
                },
                "results": results,
            },
        ],
    }

    if output_path is not None:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")

    return sarif_doc


def scan_git_diff_incremental(
    diff_text: str,
    source_root: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Incrementally parse and scan added (+) lines from a unified git diff.

    Tracks exact target file line numbers per hunk header (@@ -old,len +new,len @@).
    Suppresses deleted (-), unchanged ( ), benign fixtures, mocks, and false-positive constants.
    """
    if not isinstance(diff_text, str):
        return {
            "clean": True,
            "findings_count": 0,
            "findings": [],
            "scanned_files": [],
            "scanned_lines_count": 0,
            "diff_hunks_count": 0,
            "sarif": export_secret_scan_sarif({"findings": []}),
        }

    from .l1_primitives import scan_text_for_secrets, SECRET_SIGNATURE_CATALOG

    lines = diff_text.splitlines()
    findings: List[Dict[str, Any]] = []
    scanned_files: Set[str] = set()
    total_added_lines = 0
    total_hunks = 0

    current_file = "<unknown>"
    current_new_line = 0
    in_hunk = False

    hunk_header_re = re.compile(r"^@@\s+-[0-9]+(?:,[0-9]+)?\s+\+(?P<new_start>[0-9]+)(?:,[0-9]+)?\s+@@")

    for line in lines:
        if line.startswith("diff --git "):
            parts = line.split(" ")
            if len(parts) >= 4 and parts[3].startswith("b/"):
                current_file = parts[3][2:]
                scanned_files.add(current_file)
            in_hunk = False
            continue
        elif line.startswith("+++ b/"):
            current_file = line[6:].strip()
            if current_file != "/dev/null":
                scanned_files.add(current_file)
            in_hunk = False
            continue
        elif line.startswith("--- "):
            continue

        h_match = hunk_header_re.match(line)
        if h_match:
            total_hunks += 1
            current_new_line = int(h_match.group("new_start"))
            in_hunk = True
            continue

        if not in_hunk:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            total_added_lines += 1
            added_content = line[1:]

            lower_content = added_content.lower()
            is_benign = any(p in lower_content for p in _BENIGN_VAR_PREFIXES) or "mock" in lower_content or "dummy" in lower_content

            if not is_benign:
                text_findings = scan_text_for_secrets(added_content)
                for tf in text_findings.get("findings", []):
                    matched_val = tf.get("sample", "")
                    if _is_hex_constant(matched_val):
                        continue
                    findings.append({
                        "file_path": current_file,
                        "line_number": current_new_line,
                        "line_content": added_content.strip(),
                        "rule_id": tf.get("rule_id", "secret"),
                        "secret_type": tf.get("rule_id", "secret"),
                        "category": tf.get("category", "credential"),
                        "severity_weight": tf.get("severity_weight", 40),
                        "sample": matched_val,
                        "start_column": tf.get("span", [0, 0])[0] + 1 if tf.get("span") else 1,
                        "end_column": tf.get("span", [0, 0])[1] + 1 if tf.get("span") else len(added_content),
                    })

                assign_match = re.search(r"([A-Za-z0-9_]+)\s*[:=]\s*['\"]([^'\"]+)['\"]", added_content)
                if assign_match:
                    var_name, str_val = assign_match.group(1), assign_match.group(2)
                    if not _is_benign_variable_name(var_name) and not _is_hex_constant(str_val):
                        matched_sig = _match_credential_signature(str_val)
                        if matched_sig and not any(f["line_number"] == current_new_line for f in findings):
                            findings.append({
                                "file_path": current_file,
                                "line_number": current_new_line,
                                "line_content": added_content.strip(),
                                "rule_id": matched_sig,
                                "secret_type": matched_sig,
                                "category": "cloud_credential" if "key" in matched_sig else "scm_token",
                                "severity_weight": 45,
                                "sample": str_val[:8] + "...",
                                "start_column": assign_match.start(2) + 1,
                                "end_column": assign_match.end(2) + 1,
                            })

            current_new_line += 1
        elif line.startswith(" "):
            current_new_line += 1
        elif line.startswith("-"):
            pass

    return {
        "clean": len(findings) == 0,
        "findings_count": len(findings),
        "findings": findings,
        "scanned_files": sorted(list(scanned_files)),
        "scanned_lines_count": total_added_lines,
        "diff_hunks_count": total_hunks,
        "sarif": export_secret_scan_sarif({"findings": findings}),
    }

