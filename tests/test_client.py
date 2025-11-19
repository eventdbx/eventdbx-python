"""Tests for the TCP control-plane client."""

from __future__ import annotations

from collections import deque
from typing import Any, Mapping

import pytest

pytest.importorskip("capnp")

from eventdbx.client import (
    AggregateSortField,
    AggregateSortOption,
    EventDBXAPIError,
    EventDBXClient,
    EventDBXConnectionError,
    EventDBXHandshakeError,
    RetryOptions,
)
from eventdbx.control_schema import load_control_schema


class FakeTransport:
    def __init__(self) -> None:
        self.sent_frames: list[bytes] = []
        self._responses: deque[bytes] = deque()
        self.closed = False

    def queue_response(self, payload: bytes) -> None:
        self._responses.append(payload)

    def send_frame(self, payload: bytes) -> None:
        self.sent_frames.append(payload)

    def recv_frame(self) -> bytes:
        if not self._responses:
            raise RuntimeError("No response queued")
        return self._responses.popleft()

    def close(self) -> None:
        self.closed = True


class FlakyTransport(FakeTransport):
    """Fake transport that fails a configurable number of send attempts."""

    def __init__(self, *, fail_after: int = 1, failures: int = 1) -> None:
        super().__init__()
        self._send_calls = 0
        self._fail_after = fail_after
        self._failures_remaining = failures

    def send_frame(self, payload: bytes) -> None:
        self._send_calls += 1
        if self._send_calls > self._fail_after and self._failures_remaining > 0:
            self._failures_remaining -= 1
            raise EventDBXConnectionError("simulated transport failure")
        super().send_frame(payload)


class ResettableTransport(FakeTransport):
    """Fake transport that raises once while reading to simulate a dropped socket."""

    def __init__(self, *, fail_on_first_request: bool) -> None:
        super().__init__()
        self._recv_calls = 0
        self._fail_on_first_request = fail_on_first_request
        self.failed = False

    def recv_frame(self) -> bytes:
        self._recv_calls += 1
        # First recv is for the handshake; second recv is the first RPC response.
        if self._fail_on_first_request and not self.failed and self._recv_calls == 2:
            self.failed = True
            raise EventDBXConnectionError("connection reset mid-request")
        return super().recv_frame()


def _make_client(
    *,
    transport: FakeTransport | None = None,
    retry: RetryOptions | Mapping[str, Any] | None = None,
    verbose: bool = True,
) -> tuple[EventDBXClient, FakeTransport]:
    schema = load_control_schema()
    if transport is None:
        transport = FakeTransport()
    hello_resp = schema.ControlHelloResponse.new_message()
    hello_resp.accepted = True
    hello_resp.message = "ok"
    transport.queue_response(hello_resp.to_bytes())
    client = EventDBXClient(
        token="token",
        tenant_id="tenant",
        use_noise=False,
        transport=transport,
        retry=retry,
        verbose=verbose,
    )
    return client, transport


def test_apply_append_event_success() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("appendEvent")
    payload.eventJson = "{\"status\": \"ok\"}"
    transport.queue_response(response.to_bytes())

    result = client.apply(
        aggregate_type="order",
        aggregate_id="ord_1",
        event_type="created",
        payload_json="{}",
    )

    assert result == payload.eventJson

    with schema.ControlRequest.from_bytes(transport.sent_frames[1]) as sent_request:
        assert sent_request.id == 1
        assert sent_request.payload.which() == "appendEvent"
        append_payload = sent_request.payload.appendEvent
        assert append_payload.aggregateType == "order"
        assert append_payload.aggregateId == "ord_1"
        assert append_payload.eventType == "created"


def test_apply_returns_bool_when_verbose_disabled() -> None:
    schema = load_control_schema()
    client, transport = _make_client(verbose=False)

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("appendEvent")
    payload.eventJson = "{\"status\": \"ok\"}"
    transport.queue_response(response.to_bytes())

    result = client.apply(
        aggregate_type="order",
        aggregate_id="ord_1",
        event_type="created",
        payload_json="{}",
    )

    assert result is True


def test_events_api_returns_result() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("listEvents")
    payload.eventsJson = "[]"
    payload.nextCursor = "cursor"
    payload.hasNextCursor = True
    transport.queue_response(response.to_bytes())

    result = client.events(aggregate_type="order", aggregate_id="ord_1")

    assert result.events_json == "[]"
    assert result.next_cursor == "cursor"
    assert result.has_next_cursor is True
    with schema.ControlRequest.from_bytes(transport.sent_frames[1]) as sent_request:
        assert sent_request.payload.which() == "listEvents"


def test_events_error_payload_raises_api_error() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    error = response.payload.init("error")
    error.code = "permission_denied"
    error.message = "nope"
    transport.queue_response(response.to_bytes())

    with pytest.raises(EventDBXAPIError) as exc:
        client.events(aggregate_type="order", aggregate_id="ord_1")

    assert exc.value.code == "permission_denied"


def test_handshake_rejection_raises() -> None:
    schema = load_control_schema()
    transport = FakeTransport()
    hello_resp = schema.ControlHelloResponse.new_message()
    hello_resp.accepted = False
    hello_resp.message = "bad token"
    transport.queue_response(hello_resp.to_bytes())

    with pytest.raises(EventDBXHandshakeError):
        EventDBXClient(
            token="token",
            tenant_id="tenant",
            use_noise=False,
            transport=transport,
        )


def test_list_aggregates_via_list_api_with_sort_and_pagination_metadata() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("listAggregates")
    payload.aggregatesJson = "[]"
    payload.nextCursor = "next"
    payload.hasNextCursor = True
    transport.queue_response(response.to_bytes())

    sort_option = AggregateSortOption(field=AggregateSortField.VERSION, descending=True)
    result = client.list(take=10, sort=[sort_option], include_archived=True)

    assert result.aggregates_json == "[]"
    assert result.next_cursor == "next"
    with schema.ControlRequest.from_bytes(transport.sent_frames[1]) as sent_request:
        payload = sent_request.payload.listAggregates
        assert payload.hasSort is True
        assert payload.sort[0].field == AggregateSortField.VERSION.value
        assert payload.sort[0].descending is True
        assert payload.includeArchived is True


def test_get_aggregate_handles_not_found() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("getAggregate")
    payload.found = False
    transport.queue_response(response.to_bytes())

    result = client.get(aggregate_type="order", aggregate_id="missing")

    assert result.found is False
    assert result.aggregate_json is None


def test_verify_aggregate_returns_merkle_root() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("verifyAggregate")
    payload.merkleRoot = "abc"
    transport.queue_response(response.to_bytes())

    assert client.verify(aggregate_type="order", aggregate_id="ord") == "abc"


def test_select_aggregate_returns_projection() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("selectAggregate")
    payload.found = True
    payload.selectionJson = "{}"
    transport.queue_response(response.to_bytes())

    result = client.select(
        aggregate_type="order",
        aggregate_id="ord",
        fields=["payload.total"],
    )

    assert result.selection_json == "{}"


def test_apply_create_returns_json() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("createAggregate")
    payload.aggregateJson = "{}"
    transport.queue_response(response.to_bytes())

    assert (
        client.apply(
            aggregate_type="order",
            aggregate_id="ord",
            event_type="created",
            payload_json="{}",
            create=True,
        )
        == "{}"
    )


def test_patch_returns_event_json() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("appendEvent")
    payload.eventJson = "{}"
    transport.queue_response(response.to_bytes())

    patched = client.patch(
        aggregate_type="order",
        aggregate_id="ord",
        event_type="created",
        patches=[{"op": "replace", "path": "/total", "value": 42}],
    )

    assert patched == "{}"
    with schema.ControlRequest.from_bytes(transport.sent_frames[1]) as sent_request:
        assert sent_request.payload.which() == "patchEvent"


def test_archive_and_restore_return_json() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("setAggregateArchive")
    payload.aggregateJson = "{}"
    transport.queue_response(response.to_bytes())

    assert (
        client.archive(aggregate_type="order", aggregate_id="ord", comment="test") == "{}"
    )

    response = schema.ControlResponse.new_message()
    response.id = 2
    payload = response.payload.init("setAggregateArchive")
    payload.aggregateJson = "{}"
    transport.queue_response(response.to_bytes())

    assert client.restore(aggregate_type="order", aggregate_id="ord") == "{}"


def test_archive_returns_bool_when_verbose_disabled() -> None:
    schema = load_control_schema()
    client, transport = _make_client(verbose=False)

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("setAggregateArchive")
    payload.aggregateJson = "{}"
    transport.queue_response(response.to_bytes())

    result = client.archive(aggregate_type="order", aggregate_id="ord", comment="test")

    assert result is True


def test_retry_reuses_custom_transport_on_failure() -> None:
    schema = load_control_schema()
    flaky = FlakyTransport(fail_after=1, failures=1)
    retry_config = {"attempts": 2, "initialDelayMs": 0, "maxDelayMs": 0}
    client, transport = _make_client(transport=flaky, retry=retry_config)

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("listEvents")
    payload.eventsJson = "[]"
    transport.queue_response(response.to_bytes())

    result = client.events(aggregate_type="order", aggregate_id="ord")

    assert result.events_json == "[]"
    # send_frame should have been invoked three times: handshake + two attempts.
    assert flaky._send_calls == 3


def test_retry_reestablishes_owned_transport(monkeypatch) -> None:
    schema = load_control_schema()
    hello_resp = schema.ControlHelloResponse.new_message()
    hello_resp.accepted = True
    hello_resp.message = "ok"
    hello_bytes = hello_resp.to_bytes()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("listAggregates")
    payload.aggregatesJson = "[]"
    response_bytes = response.to_bytes()

    transports = deque(
        [
            ResettableTransport(fail_on_first_request=True),
            ResettableTransport(fail_on_first_request=False),
        ]
    )

    def fake_open(self: EventDBXClient) -> None:
        try:
            transport = transports.popleft()
        except IndexError:  # pragma: no cover - defensive
            raise AssertionError("Exceeded expected reconnect attempts")
        transport.queue_response(hello_bytes)
        transport.queue_response(response_bytes)
        self._transport = transport
        self._owned_transport = transport  # type: ignore[assignment]
        self._reset_noise()
        self._handshake()

    monkeypatch.setattr(EventDBXClient, "_open_owned_transport_once", fake_open, raising=False)

    client = EventDBXClient(
        token="token",
        tenant_id="tenant",
        retry=RetryOptions(attempts=3, initial_delay_ms=0, max_delay_ms=0),
        use_noise=False,
    )

    result = client.list()

    assert result.aggregates_json == "[]"
    # First transport should be closed after the simulated failure.
    assert transports == deque()
