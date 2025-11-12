"""Helpers for loading the Cap'n Proto control plane schema."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from typing import Any

__all__ = ["load_control_schema", "build_control_hello"]


@lru_cache(maxsize=1)
def load_control_schema() -> Any:
    """Load and cache the control Cap'n Proto schema module."""

    try:
        import capnp  # type: ignore[import-not-found]
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError(
            "pycapnp is required to use the EventDBX control schema helpers."
        ) from exc

    schema_path = resources.files("eventdbx.proto").joinpath("control.capnp")
    with resources.as_file(schema_path) as resolved:
        return capnp.load(str(resolved))


def build_control_hello(*, protocol_version: int, token: str, tenant_id: str) -> Any:
    """Create a ControlHello message with basic validation."""

    if protocol_version <= 0:
        raise ValueError("protocol_version must be greater than zero")
    if not token:
        raise ValueError("token must be provided")
    if not tenant_id:
        raise ValueError("tenant_id must be provided")

    schema = load_control_schema()
    hello = schema.ControlHello.new_message()
    hello.protocolVersion = protocol_version
    hello.token = token
    hello.tenantId = tenant_id
    return hello
