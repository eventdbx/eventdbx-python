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
    PublishTarget,
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


def test_events_accepts_filter_expression() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("listEvents")
    payload.eventsJson = "[]"
    payload.hasNextCursor = False
    transport.queue_response(response.to_bytes())

    result = client.events(
        aggregate_type="order", aggregate_id="ord_1", filter_expr="version > 2"
    )

    assert result.events_json == "[]"
    with schema.ControlRequest.from_bytes(transport.sent_frames[1]) as sent_request:
        payload = sent_request.payload.listEvents
        assert payload.hasFilter is True
        assert payload.filter == "version > 2"


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

    sort_option = AggregateSortOption(field=AggregateSortField.CREATED_AT, descending=True)
    result = client.list(take=10, sort=[sort_option], include_archived=True)

    assert result.aggregates_json == "[]"
    assert result.next_cursor == "next"
    with schema.ControlRequest.from_bytes(transport.sent_frames[1]) as sent_request:
        payload = sent_request.payload.listAggregates
        assert payload.hasSort is True
        assert payload.sort == f"{AggregateSortField.CREATED_AT.value}:desc"
        assert payload.includeArchived is True


def test_list_aggregates_accepts_sort_string() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("listAggregates")
    payload.aggregatesJson = "[]"
    transport.queue_response(response.to_bytes())

    result = client.list(sort="aggregate_type:asc, aggregate_id:desc")

    assert result.aggregates_json == "[]"
    with schema.ControlRequest.from_bytes(transport.sent_frames[1]) as sent_request:
        payload = sent_request.payload.listAggregates
        assert payload.hasSort is True
        assert payload.sort == "aggregate_type:asc, aggregate_id:desc"


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


def test_send_event_with_publish_targets() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("appendEvent")
    payload.eventJson = "{}"
    transport.queue_response(response.to_bytes())

    target = PublishTarget(plugin="webhook", mode="async", priority="high")
    result = client.send_event(
        aggregate_type="order",
        aggregate_id="ord",
        event_type="created",
        payload_json="{}",
        publish_targets=[target],
    )

    assert result == "{}"
    with schema.ControlRequest.from_bytes(transport.sent_frames[1]) as sent_request:
        append_payload = sent_request.payload.appendEvent
        assert append_payload.hasPublishTargets is True
        assert len(append_payload.publishTargets) == 1
        publish_target = append_payload.publishTargets[0]
        assert publish_target.plugin == "webhook"
        assert publish_target.mode == "async"
        assert publish_target.priority == "high"


def test_create_snapshot_returns_json() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("createSnapshot")
    payload.snapshotJson = "{}"
    transport.queue_response(response.to_bytes())

    result = client.create_snapshot(
        aggregate_type="order",
        aggregate_id="ord",
        comment="checkpoint",
    )

    assert result == "{}"
    with schema.ControlRequest.from_bytes(transport.sent_frames[1]) as sent_request:
        snapshot_payload = sent_request.payload.createSnapshot
        assert snapshot_payload.aggregateType == "order"
        assert snapshot_payload.aggregateId == "ord"
        assert snapshot_payload.hasComment is True
        assert snapshot_payload.comment == "checkpoint"


def test_tenant_schema_publish_builds_payload() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("tenantSchemaPublish")
    payload.versionId = "v1"
    payload.activated = True
    payload.skipped = False
    transport.queue_response(response.to_bytes())

    result = client.tenant_schema_publish(
        tenant_id="tenant",
        reason="deploy",
        actor="tester",
        labels=["blue", "green"],
        activate=True,
        force=True,
        reload=True,
    )

    assert result.version_id == "v1"
    assert result.activated is True
    assert result.skipped is False
    with schema.ControlRequest.from_bytes(transport.sent_frames[1]) as sent_request:
        publish_payload = sent_request.payload.tenantSchemaPublish
        assert publish_payload.tenantId == "tenant"
        assert publish_payload.hasReason is True
        assert publish_payload.reason == "deploy"
        assert publish_payload.hasActor is True
        assert publish_payload.actor == "tester"
        assert list(publish_payload.labels) == ["blue", "green"]
        assert publish_payload.activate is True
        assert publish_payload.force is True
        assert publish_payload.reload is True


def test_archive_and_restore_return_json() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("setAggregateArchive")
    payload.aggregateJson = "{}"
    transport.queue_response(response.to_bytes())

    assert client.archive(aggregate_type="order", aggregate_id="ord", note="test") == "{}"

    with schema.ControlRequest.from_bytes(transport.sent_frames[1]) as sent_request:
        archive_payload = sent_request.payload.setAggregateArchive
        assert archive_payload.hasNote is True
        assert archive_payload.note == "test"
        assert archive_payload.archived is True

    response = schema.ControlResponse.new_message()
    response.id = 2
    payload = response.payload.init("setAggregateArchive")
    payload.aggregateJson = "{}"
    transport.queue_response(response.to_bytes())

    assert client.restore(aggregate_type="order", aggregate_id="ord") == "{}"

    with schema.ControlRequest.from_bytes(transport.sent_frames[2]) as sent_request:
        restore_payload = sent_request.payload.setAggregateArchive
        assert restore_payload.hasNote is False
        assert restore_payload.archived is False


def test_archive_returns_bool_when_verbose_disabled() -> None:
    schema = load_control_schema()
    client, transport = _make_client(verbose=False)

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("setAggregateArchive")
    payload.aggregateJson = "{}"
    transport.queue_response(response.to_bytes())

    result = client.archive(aggregate_type="order", aggregate_id="ord", note="test")

    assert result is True
    with schema.ControlRequest.from_bytes(transport.sent_frames[1]) as sent_request:
        payload = sent_request.payload.setAggregateArchive
        assert payload.hasNote is True
        assert payload.note == "test"


def test_archive_accepts_legacy_comment_alias() -> None:
    schema = load_control_schema()
    client, transport = _make_client()

    response = schema.ControlResponse.new_message()
    response.id = 1
    payload = response.payload.init("setAggregateArchive")
    payload.aggregateJson = "{}"
    transport.queue_response(response.to_bytes())

    client.archive(aggregate_type="order", aggregate_id="ord", comment="legacy")

    with schema.ControlRequest.from_bytes(transport.sent_frames[1]) as sent_request:
        payload = sent_request.payload.setAggregateArchive
        assert payload.hasNote is True
        assert payload.note == "legacy"


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
