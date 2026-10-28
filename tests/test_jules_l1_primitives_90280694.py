from __future__ import annotations
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from agy_secret_shield.l1_primitives import compute_token_entropy

def test_compute_token_entropy_multi_char_single_symbol():
    assert compute_token_entropy("aaaaaaaa") == 0.0
    assert compute_token_entropy("") == 0.0
    assert compute_token_entropy("a") == 0.0
