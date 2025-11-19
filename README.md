# EventDBX Client

Official (preview) Python client for the [EventDBX](https://eventdbx.com) control-plane TCP protocol. This SDK mirrors the ergonomics of the existing JavaScript (`eventdbxjs`) and Rust (`eventdbx-client`) libraries so that Python developers can integrate EventDBX with only a few lines of code.

## Installation

```bash
python -m pip install --upgrade pip
python -m pip install eventdbx
```

> **System requirement**: `pycapnp` depends on the native Cap'n Proto toolkit. Install it first (e.g. `brew install capnp` on macOS, `apt-get install capnproto libcapnp-dev` on Debian/Ubuntu) before running `pip install`.

## Quickstart

```python
import json

from eventdbx import EventDBXClient

with EventDBXClient(token="control_token", tenant_id="tenant-123") as client:
    # Create a brand-new aggregate via the control plane
    created = client.create(
        aggregate_type="orders",
        aggregate_id="ord_123",
        event_type="created",
        payload_json=json.dumps({"total": 42.15}),
    )

    # Append follow-up events to the aggregate
    updated = client.apply(
        aggregate_type="orders",
        aggregate_id="ord_123",
        event_type="paid",
        payload_json=json.dumps({"status": "paid"}),
    )

    # List aggregates or fetch events for a specific aggregate
    aggregates = client.list(take=50)
    events_page = client.events(aggregate_type="orders", aggregate_id="ord_123")

    # Fetch full aggregate, run projections, or verify integrity
    latest = client.get(aggregate_type="orders", aggregate_id="ord_123")
    projection = client.select(
        aggregate_type="orders",
        aggregate_id="ord_123",
        fields=["payload.total", "metadata.region"],
    )
    merkle_root = client.verify(aggregate_type="orders", aggregate_id="ord_123")

    # Apply JSON Patch documents to historical events
    patched = client.patch(
        aggregate_type="orders",
        aggregate_id="ord_123",
        event_type="created",
        patches=[{"op": "replace", "path": "/total", "value": 45.10}],
    )

    # Archive / restore lifecycle management
    client.archive(aggregate_type="orders", aggregate_id="ord_123", comment="customer request")
    client.restore(aggregate_type="orders", aggregate_id="ord_123")
```

`client.create(...)` bootstraps new aggregates, `client.list(...)` pages through aggregates, and `client.events(...)` lists events for an existing aggregate (use `client.apply(...)` or the lower-level `send_event(...)` helper to append new events).

Under the hood the client establishes a persistent TCP session, performs a Noise XX handshake, and exchanges Cap'n Proto encoded control messages with the EventDBX control plane.

> **Note**: Noise transport security is enabled by default and should remain on outside of tightly controlled test scenarios.

### Verbose responses

`EventDBXClient` returns the stored JSON payloads for mutation commands by default (`apply`, `create`, `patch`, `archive`, and `restore`). To match deployments where the server is configured with `verbose_responses = false`, pass `verbose=False` to the client constructor. When verbose responses are disabled those methods resolve to a simple boolean acknowledgement instead of the serialized aggregate/event blob.

```python
client = EventDBXClient(token="control_token", tenant_id="tenant-123", verbose=False)
assert client.archive(aggregate_type="orders", aggregate_id="ord_123") is True
```

### Retry configuration

You can ask the client to automatically retry connection attempts and RPCs that fail due to transport/capnp errors. Retries are opt-in; by default each operation runs once and propagates the first error that surfaces. Pass a `retry` mapping (either snake_case or camelCase key names) or a `RetryOptions` instance to configure the behaviour:

```python
from eventdbx import EventDBXClient, RetryOptions

client = EventDBXClient(
    token="control_token",
    tenant_id="tenant-123",
    retry=RetryOptions(
        attempts=4,          # initial try + 3 retries
        initial_delay_ms=100,
        max_delay_ms=2_000,
    ),
)
```

Only IO-level errors are retried—logical API errors are still raised immediately so you can handle them explicitly.

## Control plane schemas & Noise helpers

If you need to work with the binary control plane, the package bundles the Cap'n Proto schemas and exposes a helper to load them on demand:

```python
from eventdbx.control_schema import build_control_hello

hello = build_control_hello(protocol_version=1, token="api", tenant_id="tenant")
serialized = hello.to_bytes()
```

For encrypted transport the `eventdbx.noise.NoiseSession` class wraps the `noiseprotocol` implementation using the `Noise_XX_25519_AESGCM_SHA256` pattern:

```python
from eventdbx.noise import NoiseSession

initiator = NoiseSession(is_initiator=True)
responder = NoiseSession(is_initiator=False)

step1 = initiator.write_message()
responder.read_message(step1)
```

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
pytest
```

## Release automation

Merges to `main` automatically trigger `.github/workflows/publish.yml`, which installs system dependencies, runs the test suite, builds the wheel/sdist via `python -m build`, and then publishes the artifacts to PyPI with `pypa/gh-action-pypi-publish`. To enable publishing you must create a PyPI API token with project-scoped permissions and save it as the `PYPI_API_TOKEN` repository secret; the workflow will fail safely if the secret is missing.

## Troubleshooting

- `Getting requirements to build wheel ... error`: ensure Cap'n Proto is installed (`brew install capnp` or `apt-get install capnproto libcapnp-dev`) and retry `pip install pycapnp`. Installing the wheel ahead of time with `pip install pycapnp` inside your virtualenv often resolves lingering build issues.

## Contributing

1. Fork and clone the repository, then create a feature branch.
2. Follow the development setup above (`pip install -e .[dev]`) and ensure formatting/linting still pass if you add new tools.
3. Add or update tests alongside your changes (`pytest` should be green locally).
4. Open a pull request with a clear description of the motivation and any follow-up work.
