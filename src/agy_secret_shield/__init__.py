"""AGY Secret Shield — 4-Tier (L1 -> L2 -> L3 -> L4) Secret, Cookie & Privacy Quarantine Workstation."""

from .l1_primitives import (
    SECRET_SIGNATURE_CATALOG,
    analyze_git_blob_entropy,
    compute_token_entropy,
    decode_and_scan_obfuscated_secrets,
    dpapi_seal_secret,
    dpapi_unseal_secret,
    is_dpapi_available,
    scan_text_for_secrets,
)
from .l3_pipeline import SecretShieldPipeline, run_pre_commit_dpapi_guard
from .scanner import (
    export_secret_scan_sarif,
    scan_git_diff_incremental,
    scan_python_ast_secrets,
)

__all__ = [
    "SECRET_SIGNATURE_CATALOG",
    "SecretShieldPipeline",
    "analyze_git_blob_entropy",
    "compute_token_entropy",
    "decode_and_scan_obfuscated_secrets",
    "dpapi_seal_secret",
    "dpapi_unseal_secret",
    "export_secret_scan_sarif",
    "is_dpapi_available",
    "run_pre_commit_dpapi_guard",
    "scan_git_diff_incremental",
    "scan_python_ast_secrets",
    "scan_text_for_secrets",
]


__version__ = "2.0.0"
