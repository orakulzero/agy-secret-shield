"""Locked Agile-V verification tests for Zero-Knowledge Handoff Attestation (REQ-SS-ZKP-01)."""

from __future__ import annotations

import copy
import json
from agy_secret_shield.zk_handoff_attestation import ZKHandoffAttestor


def test_create_handoff_attestation_zero_secret_leakage() -> None:
    """REQ-SS-ZKP-01: Verify create_handoff_attestation produces non-interactive proof without secret leakage."""
    attestor = ZKHandoffAttestor()
    secret_val = "super_secret_api_key_998877"
    attestation = attestor.create_handoff_attestation(
        sender_agent_id="agent_alpha",
        receiver_agent_id="agent_beta",
        task_id="task_42",
        secret_witness=secret_val,
        public_scope=["read:ast", "write:src"],
        ttl_seconds=600,
    )
    for key in (
        "attestation_id",
        "commitment_hash",
        "challenge_hash",
        "response_scalar_hex",
        "public_inputs_hash",
        "issued_at",
        "expires_at",
    ):
        assert key in attestation and attestation[key] is not None
    assert secret_val not in json.dumps(attestation)


def test_verify_handoff_attestation_accepts_valid_proof() -> None:
    """REQ-SS-ZKP-01: Verify verify_handoff_attestation accepts valid fresh attestation."""
    attestor = ZKHandoffAttestor()
    attestation = attestor.create_handoff_attestation(
        sender_agent_id="agent_alpha",
        receiver_agent_id="agent_beta",
        task_id="task_42",
        secret_witness="super_secret_api_key_998877",
        public_scope=["read:ast", "write:src"],
        ttl_seconds=600,
    )
    res = attestor.verify_handoff_attestation(
        attestation, expected_receiver_id="agent_beta", required_scope="write:src"
    )
    assert res == {"valid": True, "reason": "OK", "attestation_id": attestation["attestation_id"]}


def test_verify_handoff_attestation_rejects_tampered_proof_or_commitment() -> None:
    """REQ-SS-ZKP-01: Verify verify_handoff_attestation rejects tampered response_scalar_hex or commitment_hash."""
    attestor = ZKHandoffAttestor()
    attestation = attestor.create_handoff_attestation(
        sender_agent_id="agent_alpha",
        receiver_agent_id="agent_beta",
        task_id="task_42",
        secret_witness="super_secret_api_key_998877",
        public_scope=["read:ast", "write:src"],
        ttl_seconds=600,
    )
    tampered_scalar = copy.deepcopy(attestation)
    orig_scalar = str(tampered_scalar["response_scalar_hex"])
    tampered_scalar["response_scalar_hex"] = ("0" if orig_scalar[0] != "0" else "1") + orig_scalar[1:]
    res_scalar = attestor.verify_handoff_attestation(
        tampered_scalar, expected_receiver_id="agent_beta", required_scope="write:src"
    )
    assert res_scalar["valid"] is False
    assert "tampered" in res_scalar["reason"].lower() or "proof" in res_scalar["reason"].lower()

    attestation_2 = attestor.create_handoff_attestation(
        sender_agent_id="agent_alpha",
        receiver_agent_id="agent_beta",
        task_id="task_43",
        secret_witness="super_secret_api_key_998877",
        public_scope=["read:ast", "write:src"],
        ttl_seconds=600,
    )
    tampered_commit = copy.deepcopy(attestation_2)
    orig_commit = str(tampered_commit["commitment_hash"])
    tampered_commit["commitment_hash"] = ("0" if orig_commit[0] != "0" else "1") + orig_commit[1:]
    res_commit = attestor.verify_handoff_attestation(
        tampered_commit, expected_receiver_id="agent_beta", required_scope="write:src"
    )
    assert res_commit["valid"] is False
    assert "tampered" in res_commit["reason"].lower() or "proof" in res_commit["reason"].lower()


def test_verify_handoff_attestation_rejects_wrong_receiver_and_missing_scope() -> None:
    """REQ-SS-ZKP-01: Verify verify_handoff_attestation rejects wrong receiver and missing scope."""
    attestor = ZKHandoffAttestor()
    attestation = attestor.create_handoff_attestation(
        sender_agent_id="agent_alpha",
        receiver_agent_id="agent_beta",
        task_id="task_42",
        secret_witness="super_secret_api_key_998877",
        public_scope=["read:ast", "write:src"],
        ttl_seconds=600,
    )
    res_wrong_receiver = attestor.verify_handoff_attestation(
        attestation, expected_receiver_id="agent_rogue", required_scope="write:src"
    )
    assert res_wrong_receiver["valid"] is False

    attestation_2 = attestor.create_handoff_attestation(
        sender_agent_id="agent_alpha",
        receiver_agent_id="agent_beta",
        task_id="task_43",
        secret_witness="super_secret_api_key_998877",
        public_scope=["read:ast", "write:src"],
        ttl_seconds=600,
    )
    res_missing_scope = attestor.verify_handoff_attestation(
        attestation_2, expected_receiver_id="agent_beta", required_scope="admin:delete"
    )
    assert res_missing_scope["valid"] is False


def test_verify_handoff_attestation_rejects_expired_ttl() -> None:
    """REQ-SS-ZKP-01: Verify verify_handoff_attestation rejects expired attestation TTL."""
    attestor = ZKHandoffAttestor()
    attestation = attestor.create_handoff_attestation(
        sender_agent_id="agent_alpha",
        receiver_agent_id="agent_beta",
        task_id="task_42",
        secret_witness="super_secret_api_key_998877",
        public_scope=["read:ast", "write:src"],
        ttl_seconds=60,
    )
    res = attestor.verify_handoff_attestation(
        attestation,
        expected_receiver_id="agent_beta",
        required_scope="write:src",
        current_ts=attestation["expires_at"] + 10.0,
    )
    assert res["valid"] is False
    assert "expired" in res["reason"].lower()


def test_verify_handoff_attestation_prevents_replay_attacks() -> None:
    """REQ-SS-ZKP-01: Verify verify_handoff_attestation prevents replay attacks on second verification."""
    attestor = ZKHandoffAttestor()
    attestation = attestor.create_handoff_attestation(
        sender_agent_id="agent_alpha",
        receiver_agent_id="agent_beta",
        task_id="task_42",
        secret_witness="super_secret_api_key_998877",
        public_scope=["read:ast", "write:src"],
        ttl_seconds=600,
    )
    first_res = attestor.verify_handoff_attestation(
        attestation, expected_receiver_id="agent_beta", required_scope="write:src"
    )
    assert first_res["valid"] is True

    second_res = attestor.verify_handoff_attestation(
        attestation, expected_receiver_id="agent_beta", required_scope="write:src"
    )
    assert second_res["valid"] is False
    assert "replay" in second_res["reason"].lower()
