"""Tests for the TCP control-plane client."""

from __future__ import annotations

from collections import deque

import pytest

pytest.importorskip("capnp")

from eventdbx.client import (
    AggregateSortField,
    AggregateSortOption,
    EventDBXAPIError,
    EventDBXClient,
    EventDBXHandshakeError,
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


def _make_client(*, transport: FakeTransport | None = None) -> tuple[EventDBXClient, FakeTransport]:
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
