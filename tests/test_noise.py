"""Noise protocol helper tests."""

from __future__ import annotations

import pytest

pytest.importorskip("noise.connection")

from eventdbx.noise import NoiseSession, derive_psk


def test_noise_handshake_and_encryption_round_trip() -> None:
    psk = derive_psk("shared-secret")
    initiator = NoiseSession(is_initiator=True, psk=psk)
    responder = NoiseSession(is_initiator=False, psk=psk)

    responder.read_message(initiator.write_message())
    initiator.read_message(responder.write_message())

    assert initiator.handshake_finished
    assert responder.handshake_finished

    ciphertext = initiator.encrypt(b"payload")
    plaintext = responder.decrypt(ciphertext)
    assert plaintext == b"payload"


def test_noise_encrypt_requires_handshake() -> None:
    session = NoiseSession(is_initiator=True, psk=derive_psk("shared-secret"))

    with pytest.raises(RuntimeError):
        session.encrypt(b"oops")
