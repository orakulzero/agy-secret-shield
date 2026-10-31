"""CLI Entrypoint for AGY Secret Shield (Tier L1 -> L4)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional, Sequence

from .l1_primitives import dpapi_seal_secret, dpapi_unseal_secret
from .l3_pipeline import SecretShieldPipeline
from .l4_app import _validate_audit_repo_path


def validate_audit_args(profile: str, repo_path: Optional[str], ignore_tests: bool) -> dict:
    """Validates and sanitizes arguments for the audit command using hardened traversal checks."""
    errors: list[str] = []
    normalized = None
    if repo_path is not None:
        try:
            validated_path = _validate_audit_repo_path(repo_path)
            normalized = str(validated_path.resolve()) if validated_path else None
        except Exception as exc:
            errors.append(str(getattr(exc, "detail", exc)))
    result = {
        "valid": len(errors) == 0,
        "profile": profile,
        "errors": errors,
    }
    if result["valid"] and normalized is not None:
        result["normalized_repo_path"] = normalized
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agy-secret-shield",
        description="AGY Secret Shield — 5-Stage Secret, Cookie & Privacy Quarantine CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit_cmd = sub.add_parser("audit", help="Run 5-stage secret & privacy audit")
    audit_cmd.add_argument("--profile", default="clean_repo", help="Audit profile name")
    audit_cmd.add_argument("--repo-path", default=None, help="Optional repository path to scan")
    audit_cmd.add_argument("--ignore-tests", action="store_true", help="Exclude test/mock suites from scan")
    audit_cmd.add_argument("--json", action="store_true", help="Emit JSON output")

    seal_cmd = sub.add_parser("seal", help="Seal a secret string with Windows DPAPI")
    seal_cmd.add_argument("--secret", required=True, help="Plaintext secret to seal")
    seal_cmd.add_argument("--json", action="store_true", help="Emit JSON output")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit":
        args_validation = validate_audit_args(
            profile=args.profile,
            repo_path=args.repo_path,
            ignore_tests=getattr(args, "ignore_tests", False),
        )
        if not args_validation["valid"]:
            print(f"Error: {args_validation['errors']}")
            return 1

        pipeline = SecretShieldPipeline()
        repo_path = Path(args_validation.get("normalized_repo_path", args.repo_path)) if args.repo_path else None

        result = pipeline.audit_target(
            profile=args.profile,
            repo_path=repo_path,
            ignore_tests=getattr(args, "ignore_tests", False),
        )
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(
                f"[AGY-SECRET-SHIELD] profile={result['profile']} "
                f"clean={result['clean']} findings={result['finding_count']} "
                f"cert={result['certificate_sha256'][:16]}"
            )
        return 0

    if args.command == "seal":
        envelope = dpapi_seal_secret(args.secret)
        verified = dpapi_unseal_secret(envelope) == args.secret
        payload = {"ok": True, "roundtrip_verified": verified, "envelope": envelope}
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"Tag: {envelope['redacted_tag']} (engine={envelope['engine']})")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
