import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import pytest
from agy_secret_shield.scanner import scan_python_ast_secrets

def test_complex_fstring_no_false_positive():
    """Verify scanner ignores complex f-strings that shouldn't be flagged as secrets."""
    source_code = """
import os
import datetime

def get_env():
    return "prod"

# 1. Non-sensitive variable with multiple static parts and non-string interpolations
complex_string = f"prefix-{os.name}-mid-{get_env()}-end-{123}-{True}"

# 2. Sensitive variable with 0 static string parts (only expressions)
api_key = f"{os.getenv('PREFIX')}{get_env()}{datetime.datetime.now()}"

# 3. Sensitive variable with exactly 1 static string part
secret = f"env_{get_env()}{123}"

# 4. f-string passed as argument where static parts do not reconstruct to secret
Client(api_key=f"prod_{get_env()}")

# 5. os.getenv fallback using f-string with 1 static part
os.getenv("SECRET_KEY", f"default_{get_env()}")

# 6. Benign mock variable with multiple static parts (should be filtered)
mock_api_key = f"sk-{os.name}-dummy-{123}-{True}"
"""
    result = scan_python_ast_secrets(source_code, filename="test.py")
    
    assert result["clean"] is True, f"Expected clean, got findings: {result['findings']}"
    assert len(result["findings"]) == 0
    assert len(result["taint_flows"]) == 0

def test_edge_cases_fstring_flags():
    """Verify boundary conditions where f-strings MIGHT actually flag correctly or filter."""
    source_code = """
# Multiple static parts on sensitive variable DOES flag as taint_concatenation
# since len(parts) > 1 and is_sensitive_var is True
api_key = f"part1-{var1}-part2-{var2}"

# F-string forming a cryptographic hex constant should be filtered
hex_val = f"{'a'*32}"
"""
    result = scan_python_ast_secrets(source_code, filename="test.py")
    
    assert result["clean"] is False
    assert len(result["findings"]) == 1
    assert result["findings"][0]["variable_or_arg"] == "api_key"
    assert result["findings"][0]["category"] == "taint_concatenation"

def test_fstring_with_no_string_constants():
    """Ensure f-string with only variables does not fail."""
    source_code = """
token = f"{a}{b}{c}"
"""
    result = scan_python_ast_secrets(source_code)
    assert result["clean"] is True
    assert len(result["findings"]) == 0
