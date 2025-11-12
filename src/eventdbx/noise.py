"""Noise protocol helpers for EventDBX control plane sessions."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from noise.connection import Keypair, NoiseConnection

DEFAULT_NOISE_PROTOCOL = "Noise_XX_25519_AESGCM_SHA256"
DEFAULT_NOISE_PROLOGUE = b"eventdbx-control"

__all__ = [
    "DEFAULT_NOISE_PROTOCOL",
    "DEFAULT_NOISE_PROLOGUE",
    "NoiseSession",
    "NoiseHandshake",
]


@dataclass(slots=True)
class NoiseHandshake:
    """Captures the final handshake artefacts for auditing/logging."""

    handshake_hash: bytes
    remote_static: Optional[bytes]


class NoiseSession:
    """Wrapper around ``NoiseConnection`` with guardrails for EventDBX."""

    def __init__(
        self,
        *,
        is_initiator: bool,
        protocol_name: str | bytes = DEFAULT_NOISE_PROTOCOL,
        prologue: bytes = DEFAULT_NOISE_PROLOGUE,
        local_static: bytes | None = None,
        remote_static: bytes | None = None,
    ) -> None:
        protocol_value = protocol_name.encode() if isinstance(protocol_name, str) else protocol_name
        self._connection = NoiseConnection.from_name(protocol_value)
        if is_initiator:
            self._connection.set_as_initiator()
        else:
            self._connection.set_as_responder()
        self._connection.set_prologue(prologue)
        local_static_key = local_static or os.urandom(32)
        self._connection.set_keypair_from_private_bytes(Keypair.STATIC, local_static_key)
        if remote_static is not None:
            self._connection.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, remote_static)
        self._connection.start_handshake()

    @property
    def handshake_finished(self) -> bool:
        return self._connection.handshake_finished

    def write_message(self, payload: bytes = b"") -> bytes:
        return self._connection.write_message(payload)

    def read_message(self, message: bytes) -> bytes:
        return self._connection.read_message(message)

    def finalize_handshake(self) -> NoiseHandshake:
        if not self._connection.handshake_finished:
            raise RuntimeError("Handshake is not complete")
        remote_key: Optional[bytes]
        try:
            remote_key = self._connection.get_remote_public_key()
        except Exception:  # pragma: no cover - backend specific
            remote_key = None
        return NoiseHandshake(
            handshake_hash=self._connection.handshake_hash,
            remote_static=remote_key,
        )

    def encrypt(self, plaintext: bytes, *, aad: bytes | None = None) -> bytes:
        if not self._connection.handshake_finished:
            raise RuntimeError("Cannot encrypt before completing the handshake")
        args = (aad or b"", plaintext)
        try:
            return self._connection.encrypt(*args)
        except TypeError:
            if aad not in (None, b""):
                raise RuntimeError("The configured Noise backend does not support AAD") from None
            return self._connection.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes, *, aad: bytes | None = None) -> bytes:
        if not self._connection.handshake_finished:
            raise RuntimeError("Cannot decrypt before completing the handshake")
        args = (aad or b"", ciphertext)
        try:
            return self._connection.decrypt(*args)
        except TypeError:
            if aad not in (None, b""):
                raise RuntimeError("The configured Noise backend does not support AAD") from None
            return self._connection.decrypt(ciphertext)
