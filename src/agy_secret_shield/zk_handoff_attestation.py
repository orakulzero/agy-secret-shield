"""Zero-Knowledge Handoff Attestation via Schnorr Fiat-Shamir NIZK (REQ-SS-ZKP-01)."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any

# Secp256k1 field prime p = 2^256 - 2^32 - 977 and generator g = 5 in Z_p*
_FIELD_PRIME: int = (1 << 256) - (1 << 32) - 977
_GROUP_ORDER: int = _FIELD_PRIME - 1
_GENERATOR: int = 5


class ZKHandoffAttestor:
    """Non-Interactive Zero-Knowledge (Fiat-Shamir Schnorr) Handoff Attestor (REQ-SS-ZKP-01)."""

    def __init__(self) -> None:
        self._consumed_attestations: set[str] = set()

    @staticmethod
    def _derive_witness_scalar(secret_witness: str) -> int:
        digest = hashlib.sha256(f"zk-witness:{secret_witness}".encode()).hexdigest()
        scalar = int(digest, 16) % (_GROUP_ORDER - 1)
        return scalar + 1

    @staticmethod
    def _compute_public_inputs_hash(
        attestation_id: str,
        sender_agent_id: str,
        receiver_agent_id: str,
        task_id: str,
        public_scope: list[str],
        issued_at: float,
        expires_at: float,
        witness_pub_hex: str,
    ) -> str:
        payload = json.dumps(
            {
                "attestation_id": attestation_id,
                "sender_agent_id": sender_agent_id,
                "receiver_agent_id": receiver_agent_id,
                "task_id": task_id,
                "public_scope": list(public_scope),
                "issued_at": issued_at,
                "expires_at": expires_at,
                "witness_pub_hex": witness_pub_hex,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _compute_challenge_hash(commitment_hash: str, public_inputs_hash: str) -> str:
        raw = f"fiat-shamir:{commitment_hash}:{public_inputs_hash}".encode()
        return hashlib.sha256(raw).hexdigest()

    def create_handoff_attestation(
        self,
        sender_agent_id: str,
        receiver_agent_id: str,
        task_id: str,
        secret_witness: str,
        public_scope: list[str],
        ttl_seconds: int = 600,
    ) -> dict[str, Any]:
        """Generate a Fiat-Shamir Schnorr NIZK attestation without exposing secret_witness."""
        if not secret_witness:
            raise ValueError("secret_witness must be non-empty")

        issued_at = float(time.time())
        expires_at = issued_at + float(ttl_seconds)
        attestation_id = f"zk-att-{secrets.token_hex(8)}"

        witness_x = self._derive_witness_scalar(secret_witness)
        witness_pub_y = pow(_GENERATOR, witness_x, _FIELD_PRIME)
        witness_pub_hex = f"{witness_pub_y:064x}"

        nonce_r = secrets.randbelow(_GROUP_ORDER - 1) + 1
        commitment_t = pow(_GENERATOR, nonce_r, _FIELD_PRIME)
        commitment_hash = f"{commitment_t:064x}"

        public_inputs_hash = self._compute_public_inputs_hash(
            attestation_id=attestation_id,
            sender_agent_id=sender_agent_id,
            receiver_agent_id=receiver_agent_id,
            task_id=task_id,
            public_scope=public_scope,
            issued_at=issued_at,
            expires_at=expires_at,
            witness_pub_hex=witness_pub_hex,
        )
        challenge_hash = self._compute_challenge_hash(commitment_hash, public_inputs_hash)
        challenge_c = int(challenge_hash, 16) % _GROUP_ORDER

        response_s = (nonce_r + challenge_c * witness_x) % _GROUP_ORDER
        response_scalar_hex = f"{response_s:064x}"

        return {
            "attestation_id": attestation_id,
            "sender_agent_id": sender_agent_id,
            "receiver_agent_id": receiver_agent_id,
            "task_id": task_id,
            "public_scope": list(public_scope),
            "commitment_hash": commitment_hash,
            "challenge_hash": challenge_hash,
            "response_scalar_hex": response_scalar_hex,
            "public_inputs_hash": public_inputs_hash,
            "witness_pub_hex": witness_pub_hex,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }

    def verify_handoff_attestation(
        self,
        attestation: dict[str, Any],
        expected_receiver_id: str,
        required_scope: str,
        current_ts: float | None = None,
    ) -> dict[str, Any]:
        """Verify NIZK handoff attestation proof, receiver binding, scope, TTL, and replay status."""
        attestation_id = str(attestation.get("attestation_id", ""))
        if attestation_id in self._consumed_attestations:
            return {
                "valid": False,
                "reason": "Replay attack prevented: attestation already consumed",
                "attestation_id": attestation_id,
            }

        now = float(current_ts) if current_ts is not None else float(time.time())
        expires_at = float(attestation.get("expires_at", 0.0))
        if now > expires_at:
            return {
                "valid": False,
                "reason": "Attestation TTL expired",
                "attestation_id": attestation_id,
            }

        if attestation.get("receiver_agent_id") != expected_receiver_id:
            return {
                "valid": False,
                "reason": "Expected receiver agent mismatch",
                "attestation_id": attestation_id,
            }

        scopes = attestation.get("public_scope", [])
        if required_scope not in scopes:
            return {
                "valid": False,
                "reason": f"Required scope '{required_scope}' not granted",
                "attestation_id": attestation_id,
            }

        try:
            expected_pub_hash = self._compute_public_inputs_hash(
                attestation_id=attestation_id,
                sender_agent_id=str(attestation["sender_agent_id"]),
                receiver_agent_id=str(attestation["receiver_agent_id"]),
                task_id=str(attestation["task_id"]),
                public_scope=list(scopes),
                issued_at=float(attestation["issued_at"]),
                expires_at=expires_at,
                witness_pub_hex=str(attestation["witness_pub_hex"]),
            )
            commitment_hash = str(attestation["commitment_hash"])
            expected_challenge = self._compute_challenge_hash(commitment_hash, expected_pub_hash)
            if (
                expected_pub_hash != attestation.get("public_inputs_hash")
                or expected_challenge != attestation.get("challenge_hash")
            ):
                return {
                    "valid": False,
                    "reason": "Tampered commitment or public input proof mismatch",
                    "attestation_id": attestation_id,
                }

            commitment_t = int(commitment_hash, 16)
            witness_pub_y = int(str(attestation["witness_pub_hex"]), 16)
            challenge_c = int(expected_challenge, 16) % _GROUP_ORDER
            response_s = int(str(attestation["response_scalar_hex"]), 16)

            if not (0 <= response_s < _GROUP_ORDER) or not (1 <= commitment_t < _FIELD_PRIME):
                return {
                    "valid": False,
                    "reason": "Tampered proof scalar or commitment out of group bounds",
                    "attestation_id": attestation_id,
                }

            lhs = pow(_GENERATOR, response_s, _FIELD_PRIME)
            rhs = (commitment_t * pow(witness_pub_y, challenge_c, _FIELD_PRIME)) % _FIELD_PRIME
            if lhs != rhs:
                return {
                    "valid": False,
                    "reason": "Tampered proof: Schnorr verification equation failed",
                    "attestation_id": attestation_id,
                }
        except (KeyError, ValueError, TypeError):
            return {
                "valid": False,
                "reason": "Tampered or malformed proof payload",
                "attestation_id": attestation_id,
            }

        self._consumed_attestations.add(attestation_id)
        return {"valid": True, "reason": "OK", "attestation_id": attestation_id}
