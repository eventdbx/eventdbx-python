"""Tests for the Cap'n Proto helpers."""

from __future__ import annotations

import pytest

capnp = pytest.importorskip("capnp")

from eventdbx.control_schema import build_control_hello, load_control_schema


def test_load_control_schema_cached() -> None:
    module_a = load_control_schema()
    module_b = load_control_schema()
    assert module_a is module_b
    assert hasattr(module_a, "ControlHello")


def test_build_control_hello_roundtrip() -> None:
    hello = build_control_hello(protocol_version=1, token="tok", tenant_id="tenant")
    data = hello.to_bytes()
    schema = load_control_schema()
    with schema.ControlHello.from_bytes(data) as decoded:
        assert decoded.protocolVersion == 1
        assert decoded.token == "tok"
        assert decoded.tenantId == "tenant"


@pytest.mark.parametrize(
    "protocol, token, tenant",
    [
        (0, "tok", "tenant"),
        (1, "", "tenant"),
        (1, "tok", ""),
    ],
)
def test_build_control_hello_validation(protocol: int, token: str, tenant: str) -> None:
    with pytest.raises(ValueError):
        build_control_hello(protocol_version=protocol, token=token, tenant_id=tenant)
