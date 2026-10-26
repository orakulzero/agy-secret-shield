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
