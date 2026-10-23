"""AGY Secret Shield — 4-Tier (L1 -> L2 -> L3 -> L4) Secret, Cookie & Privacy Quarantine Workstation."""

from .l1_primitives import (
    SECRET_SIGNATURE_CATALOG,
    compute_token_entropy,
    dpapi_seal_secret,
    dpapi_unseal_secret,
    is_dpapi_available,
    scan_text_for_secrets,
)
from .l3_pipeline import SecretShieldPipeline

__all__ = [
    "SECRET_SIGNATURE_CATALOG",
    "SecretShieldPipeline",
    "compute_token_entropy",
    "dpapi_seal_secret",
    "dpapi_unseal_secret",
    "is_dpapi_available",
    "scan_text_for_secrets",
]

__version__ = "1.0.0"
