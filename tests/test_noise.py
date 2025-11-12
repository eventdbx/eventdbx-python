"""Noise protocol helper tests."""

from __future__ import annotations

import pytest

pytest.importorskip("noise.connection")

from eventdbx.noise import NoiseSession


def test_noise_handshake_and_encryption_round_trip() -> None:
    initiator = NoiseSession(is_initiator=True)
    responder = NoiseSession(is_initiator=False)

    responder.read_message(initiator.write_message())
    initiator.read_message(responder.write_message())
    responder.read_message(initiator.write_message())

    assert initiator.handshake_finished
    assert responder.handshake_finished

    ciphertext = initiator.encrypt(b"payload")
    plaintext = responder.decrypt(ciphertext)
    assert plaintext == b"payload"


def test_noise_encrypt_requires_handshake() -> None:
    session = NoiseSession(is_initiator=True)

    with pytest.raises(RuntimeError):
        session.encrypt(b"oops")
