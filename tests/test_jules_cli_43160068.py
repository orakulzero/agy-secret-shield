import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure src is in the python path
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from agy_secret_shield.cli import main


@pytest.fixture
def mock_l1_primitives():
    with patch("agy_secret_shield.cli.dpapi_seal_secret") as mock_seal, \
         patch("agy_secret_shield.cli.dpapi_unseal_secret") as mock_unseal:
        
        # Configure mock return values for empty string
        mock_seal.return_value = {
            "ciphertext": "dummy_sealed_empty_string",
            "redacted_tag": "tag_empty",
            "engine": "dummy_engine"
        }
        mock_unseal.return_value = ""
        
        yield mock_seal, mock_unseal


def test_seal_empty_string_json(mock_l1_primitives, capsys):
    mock_seal, mock_unseal = mock_l1_primitives
    
    exit_code = main(["seal", "--secret", "", "--json"])
    
    assert exit_code == 0
    mock_seal.assert_called_once_with("")
    mock_unseal.assert_called_once_with(mock_seal.return_value)
    
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    
    assert output["ok"] is True
    assert output["roundtrip_verified"] is True
    assert output["envelope"] == mock_seal.return_value


def test_seal_empty_string_no_json(mock_l1_primitives, capsys):
    mock_seal, mock_unseal = mock_l1_primitives
    
    exit_code = main(["seal", "--secret", ""])
    
    assert exit_code == 0
    mock_seal.assert_called_once_with("")
    mock_unseal.assert_called_once_with(mock_seal.return_value)
    
    captured = capsys.readouterr()
    
    assert "Tag: tag_empty (engine=dummy_engine)" in captured.out
