"""TCP control-plane client for EventDBX."""

from __future__ import annotations

import json
import socket
import struct
import warnings
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping, Optional, Protocol, Sequence, TypeVar

from .control_schema import build_control_hello, load_control_schema
from .noise import NoiseSession

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 6363
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 15.0

__all__ = [
    "EventDBXClient",
    "EventDBXAPIError",
    "EventDBXHandshakeError",
    "EventDBXConnectionError",
    "ListAggregatesResult",
    "ListEventsResult",
    "GetAggregateResult",
    "SelectAggregateResult",
    "AggregateSortField",
    "AggregateSortOption",
]


T = TypeVar("T")


@contextmanager
def _capnp_message(message: Any) -> Any:
    """Yield Cap'n Proto messages across both builder and reader APIs."""

    if hasattr(message, "__enter__"):
        with message as resolved:
            yield resolved
    else:
        yield message


class FrameTransport(Protocol):
    """Abstraction for framed, bidirectional byte streams."""

    def send_frame(self, payload: bytes) -> None:  # pragma: no cover - protocol definition
        ...

    def recv_frame(self) -> bytes:  # pragma: no cover - protocol definition
        ...

    def close(self) -> None:  # pragma: no cover - protocol definition
        ...


class EventDBXConnectionError(RuntimeError):
    """Raised when the TCP connection is disrupted."""


class EventDBXHandshakeError(EventDBXConnectionError):
    """Raised when the server rejects the control-plane handshake."""


@dataclass(slots=True)
class ListAggregatesResult:
    aggregates_json: str
    next_cursor: Optional[str]
    has_next_cursor: bool


@dataclass(slots=True)
class ListEventsResult:
    events_json: str
    next_cursor: Optional[str]
    has_next_cursor: bool


@dataclass(slots=True)
class GetAggregateResult:
    found: bool
    aggregate_json: Optional[str]


@dataclass(slots=True)
class SelectAggregateResult:
    found: bool
    selection_json: Optional[str]


class AggregateSortField(str, Enum):
    AGGREGATE_TYPE = "aggregateType"
    AGGREGATE_ID = "aggregateId"
    VERSION = "version"
    MERKLE_ROOT = "merkleRoot"
    ARCHIVED = "archived"


@dataclass(slots=True)
class AggregateSortOption:
    field: AggregateSortField
    descending: bool = False


@dataclass(slots=True)
class EventDBXAPIError(RuntimeError):
    """Represents logical errors returned by the EventDBX API."""

    code: str
    message: str

    def __str__(self) -> str:  # pragma: no cover - trivial repr
        return f"{self.code}: {self.message}"


class _SocketTransport:
    """Length-prefixed framing over a raw TCP socket."""

    def __init__(self, sock: socket.socket) -> None:
        self._socket = sock

    def send_frame(self, payload: bytes) -> None:
        header = struct.pack(">I", len(payload))
        self._socket.sendall(header + payload)

    def recv_frame(self) -> bytes:
        size_data = self._recv_exact(4)
        (size,) = struct.unpack(">I", size_data)
        return self._recv_exact(size)

    def close(self) -> None:
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._socket.close()

    def _recv_exact(self, size: int) -> bytes:
        data = bytearray()
        remaining = size
        while remaining > 0:
            chunk = self._socket.recv(remaining)
            if not chunk:
                raise EventDBXConnectionError("Connection closed while reading from socket")
            data.extend(chunk)
            remaining -= len(chunk)
        return bytes(data)


class EventDBXClient:
    """Binary TCP client that speaks the EventDBX control protocol."""

    def __init__(
        self,
        *,
        token: str,
        tenant_id: str,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        protocol_version: int = 1,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
        use_noise: bool = True,
        transport: FrameTransport | None = None,
    ) -> None:
        if not token:
            raise ValueError("token must be provided")
        if not tenant_id:
            raise ValueError("tenant_id must be provided")

        self._token = token
        self._tenant_id = tenant_id
        self._protocol_version = protocol_version
        self._schema = load_control_schema()
        self._request_id = 0
        self._owned_transport: Optional[_SocketTransport] = None

        if transport is None:
            sock = socket.create_connection((host, port), timeout=connect_timeout)
            sock.settimeout(read_timeout)
            transport = _SocketTransport(sock)
            self._owned_transport = transport

        self._transport: FrameTransport | None = transport
        if not use_noise:
            warnings.warn(
                "Disabling Noise is intended for testing only; the EventDBX control plane uses "
                "Noise XX by default.",
                RuntimeWarning,
                stacklevel=2,
            )
        self._noise = NoiseSession(is_initiator=True) if use_noise else None
        self._handshake()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def close(self) -> None:
        if self._owned_transport is not None:
            self._owned_transport.close()
            self._owned_transport = None
        self._transport = None

    def __enter__(self) -> "EventDBXClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def connected(self) -> bool:
        return self._transport is not None

    # ------------------------------------------------------------------
    # High-level control commands
    # ------------------------------------------------------------------

    def apply(
        self,
        *,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        payload_json: str,
        note: str | None = None,
        metadata_json: str | None = None,
        create: bool = False,
    ) -> str:
        """Apply an event. Set ``create`` to True to create a brand-new aggregate."""

        if create:
            return self.create_aggregate(
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
                event_type=event_type,
                payload_json=payload_json,
                note=note,
                metadata_json=metadata_json,
            )

        return self.send_event(
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            event_type=event_type,
            payload_json=payload_json,
            note=note,
            metadata_json=metadata_json,
        )

    def create(
        self,
        *,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        payload_json: str,
        note: str | None = None,
        metadata_json: str | None = None,
    ) -> str:
        """Create a brand-new aggregate and return the aggregate JSON blob."""

        return self.create_aggregate(
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            event_type=event_type,
            payload_json=payload_json,
            note=note,
            metadata_json=metadata_json,
        )

    def list(
        self,
        *,
        cursor: str | None = None,
        take: int | None = None,
        filter_expr: str | None = None,
        sort: list[AggregateSortOption] | None = None,
        include_archived: bool | None = None,
        archived_only: bool | None = None,
    ) -> ListAggregatesResult:
        """List aggregates with optional filtering, sorting and pagination."""

        return self.list_aggregates(
            cursor=cursor,
            take=take,
            filter_expr=filter_expr,
            sort=sort,
            include_archived=include_archived,
            archived_only=archived_only,
        )

    def events(
        self,
        *,
        aggregate_type: str,
        aggregate_id: str,
        cursor: str | None = None,
        take: int | None = None,
    ) -> ListEventsResult:
        """Return a page of events for a specific aggregate."""

        return self.list_events(
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            cursor=cursor,
            take=take,
        )

    def get(self, *, aggregate_type: str, aggregate_id: str) -> GetAggregateResult:
        """Fetch a single aggregate."""

        return self.get_aggregate(aggregate_type=aggregate_type, aggregate_id=aggregate_id)

    def select(
        self,
        *,
        aggregate_type: str,
        aggregate_id: str,
        fields: list[str],
    ) -> SelectAggregateResult:
        """Run a projection query against an aggregate."""

        return self.select_aggregate(
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            fields=fields,
        )

    def patch(
        self,
        *,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        patches: Sequence[Mapping[str, Any]],
        note: str | None = None,
        metadata_json: str | None = None,
    ) -> str:
        """Patch an existing event using a JSON patch document list."""

        if not patches:
            raise ValueError("patches must contain at least one entry")
        return self.patch_event(
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            event_type=event_type,
            patches=patches,
            note=note,
            metadata_json=metadata_json,
        )

    def archive(
        self,
        *,
        aggregate_type: str,
        aggregate_id: str,
        comment: str | None = None,
    ) -> str:
        """Archive an aggregate."""

        return self.set_aggregate_archive(
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            archived=True,
            comment=comment,
        )

    def restore(
        self,
        *,
        aggregate_type: str,
        aggregate_id: str,
        comment: str | None = None,
    ) -> str:
        """Restore an archived aggregate."""

        return self.set_aggregate_archive(
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            archived=False,
            comment=comment,
        )

    def verify(self, *, aggregate_type: str, aggregate_id: str) -> str:
        """Return the merkle root for an aggregate."""

        return self.verify_aggregate(aggregate_type=aggregate_type, aggregate_id=aggregate_id)

    def send_event(
        self,
        *,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        payload_json: str,
        note: str | None = None,
        metadata_json: str | None = None,
    ) -> str:
        """Append a new event serialized as JSON; returns the Event JSON blob."""

        if not aggregate_type or not aggregate_id or not event_type:
            raise ValueError("aggregate_type, aggregate_id and event_type must be provided")

        def build_payload(container):
            request = container.init("appendEvent")
            request.token = self._token
            request.aggregateType = aggregate_type
            request.aggregateId = aggregate_id
            request.eventType = event_type
            request.payloadJson = payload_json
            if note is not None:
                request.note = note
                request.hasNote = True
            if metadata_json is not None:
                request.metadataJson = metadata_json
                request.hasMetadata = True

        def handle_payload(payload: Any) -> str:
            if payload.which() != "appendEvent":
                raise EventDBXConnectionError("Unexpected response type for appendEvent")
            return payload.appendEvent.eventJson

        return self._send_request(build_payload, handle_payload)

    def list_events(
        self,
        *,
        aggregate_type: str,
        aggregate_id: str,
        cursor: str | None = None,
        take: int | None = None,
    ) -> ListEventsResult:
        """Fetch a page of events as JSON plus pagination metadata."""

        if not aggregate_type or not aggregate_id:
            raise ValueError("aggregate_type and aggregate_id must be provided")

        def build_payload(container):
            request = container.init("listEvents")
            request.token = self._token
            request.aggregateType = aggregate_type
            request.aggregateId = aggregate_id
            if cursor is not None:
                request.cursor = cursor
                request.hasCursor = True
            if take is not None:
                request.take = take
                request.hasTake = True

        def handle_payload(payload: Any) -> ListEventsResult:
            if payload.which() != "listEvents":
                raise EventDBXConnectionError("Unexpected response type for listEvents")
            data = payload.listEvents
            next_cursor = data.nextCursor if data.hasNextCursor else None
            return ListEventsResult(
                events_json=data.eventsJson,
                next_cursor=next_cursor,
                has_next_cursor=data.hasNextCursor,
            )

        return self._send_request(build_payload, handle_payload)

    def list_aggregates(
        self,
        *,
        cursor: str | None = None,
        take: int | None = None,
        filter_expr: str | None = None,
        sort: list[AggregateSortOption] | None = None,
        include_archived: bool | None = None,
        archived_only: bool | None = None,
    ) -> ListAggregatesResult:
        """List aggregates and return pagination info."""

        def build_payload(container):
            request = container.init("listAggregates")
            request.token = self._token
            if cursor is not None:
                request.cursor = cursor
                request.hasCursor = True
            if take is not None:
                request.take = take
                request.hasTake = True
            if filter_expr is not None:
                request.filter = filter_expr
                request.hasFilter = True
            if sort:
                request.hasSort = True
                sort_list = request.init("sort", len(sort))
                for idx, option in enumerate(sort):
                    sort_list[idx].field = option.field.value
                    sort_list[idx].descending = option.descending
            if include_archived is not None:
                request.includeArchived = include_archived
            if archived_only is not None:
                request.archivedOnly = archived_only

        def handle_payload(payload: Any) -> ListAggregatesResult:
            if payload.which() != "listAggregates":
                raise EventDBXConnectionError("Unexpected response type for listAggregates")
            data = payload.listAggregates
            next_cursor = data.nextCursor if data.hasNextCursor else None
            return ListAggregatesResult(
                aggregates_json=data.aggregatesJson,
                next_cursor=next_cursor,
                has_next_cursor=data.hasNextCursor,
            )

        return self._send_request(build_payload, handle_payload)

    def get_aggregate(self, *, aggregate_type: str, aggregate_id: str) -> GetAggregateResult:
        """Fetch a single aggregate."""

        if not aggregate_type or not aggregate_id:
            raise ValueError("aggregate_type and aggregate_id must be provided")

        def build_payload(container):
            request = container.init("getAggregate")
            request.token = self._token
            request.aggregateType = aggregate_type
            request.aggregateId = aggregate_id

        def handle_payload(payload: Any) -> GetAggregateResult:
            if payload.which() != "getAggregate":
                raise EventDBXConnectionError("Unexpected response type for getAggregate")
            data = payload.getAggregate
            aggregate_json = data.aggregateJson if data.found else None
            return GetAggregateResult(found=data.found, aggregate_json=aggregate_json)

        return self._send_request(build_payload, handle_payload)

    def verify_aggregate(self, *, aggregate_type: str, aggregate_id: str) -> str:
        """Return the merkle root for the aggregate."""

        if not aggregate_type or not aggregate_id:
            raise ValueError("aggregate_type and aggregate_id must be provided")

        def build_payload(container):
            request = container.init("verifyAggregate")
            request.aggregateType = aggregate_type
            request.aggregateId = aggregate_id

        def handle_payload(payload: Any) -> str:
            if payload.which() != "verifyAggregate":
                raise EventDBXConnectionError("Unexpected response type for verifyAggregate")
            return payload.verifyAggregate.merkleRoot

        return self._send_request(build_payload, handle_payload)

    def select_aggregate(
        self,
        *,
        aggregate_type: str,
        aggregate_id: str,
        fields: list[str],
    ) -> SelectAggregateResult:
        """Run a projection query against an aggregate."""

        if not aggregate_type or not aggregate_id:
            raise ValueError("aggregate_type and aggregate_id must be provided")
        if not fields:
            raise ValueError("fields must contain at least one entry")

        def build_payload(container):
            request = container.init("selectAggregate")
            request.token = self._token
            request.aggregateType = aggregate_type
            request.aggregateId = aggregate_id
            field_list = request.init("fields", len(fields))
            for idx, field in enumerate(fields):
                field_list[idx] = field

        def handle_payload(payload: Any) -> SelectAggregateResult:
            if payload.which() != "selectAggregate":
                raise EventDBXConnectionError("Unexpected response type for selectAggregate")
            data = payload.selectAggregate
            selection_json = data.selectionJson if data.found else None
            return SelectAggregateResult(found=data.found, selection_json=selection_json)

        return self._send_request(build_payload, handle_payload)

    def create_aggregate(
        self,
        *,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        payload_json: str,
        note: str | None = None,
        metadata_json: str | None = None,
    ) -> str:
        """Create a brand new aggregate and return the aggregate JSON blob."""

        if not aggregate_type or not aggregate_id or not event_type:
            raise ValueError("aggregate_type, aggregate_id and event_type must be provided")

        def build_payload(container):
            request = container.init("createAggregate")
            request.token = self._token
            request.aggregateType = aggregate_type
            request.aggregateId = aggregate_id
            request.eventType = event_type
            request.payloadJson = payload_json
            if note is not None:
                request.note = note
                request.hasNote = True
            if metadata_json is not None:
                request.metadataJson = metadata_json
                request.hasMetadata = True

        def handle_payload(payload: Any) -> str:
            if payload.which() != "createAggregate":
                raise EventDBXConnectionError("Unexpected response type for createAggregate")
            return payload.createAggregate.aggregateJson

        return self._send_request(build_payload, handle_payload)

    def patch_event(
        self,
        *,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        patches: Sequence[Mapping[str, Any]],
        note: str | None = None,
        metadata_json: str | None = None,
    ) -> str:
        """Patch an existing event; returns the updated event JSON."""

        if not aggregate_type or not aggregate_id or not event_type:
            raise ValueError("aggregate_type, aggregate_id and event_type must be provided")
        if not patches:
            raise ValueError("patches must contain at least one entry")

        def build_payload(container):
            request = container.init("patchEvent")
            request.token = self._token
            request.aggregateType = aggregate_type
            request.aggregateId = aggregate_id
            request.eventType = event_type
            request.patchJson = json.dumps(patches)
            if note is not None:
                request.note = note
                request.hasNote = True
            if metadata_json is not None:
                request.metadataJson = metadata_json
                request.hasMetadata = True

        def handle_payload(payload: Any) -> str:
            if payload.which() != "appendEvent":
                raise EventDBXConnectionError("Unexpected response type for patchEvent")
            return payload.appendEvent.eventJson

        return self._send_request(build_payload, handle_payload)

    def set_aggregate_archive(
        self,
        *,
        aggregate_type: str,
        aggregate_id: str,
        archived: bool,
        comment: str | None = None,
    ) -> str:
        """Toggle the archive state for an aggregate."""

        if not aggregate_type or not aggregate_id:
            raise ValueError("aggregate_type and aggregate_id must be provided")

        def build_payload(container):
            request = container.init("setAggregateArchive")
            request.token = self._token
            request.aggregateType = aggregate_type
            request.aggregateId = aggregate_id
            request.archived = archived
            if comment:
                request.comment = comment
                request.hasComment = True
            elif comment is not None:
                request.comment = ""
                request.hasComment = True

        def handle_payload(payload: Any) -> str:
            if payload.which() != "setAggregateArchive":
                raise EventDBXConnectionError("Unexpected response type for setAggregateArchive")
            return payload.setAggregateArchive.aggregateJson

        return self._send_request(build_payload, handle_payload)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _handshake(self) -> None:
        if self._transport is None:
            raise EventDBXConnectionError("Transport is not available")

        hello = build_control_hello(
            protocol_version=self._protocol_version,
            token=self._token,
            tenant_id=self._tenant_id,
        )

        if self._noise is not None:
            first = self._noise.write_message()
            self._transport.send_frame(first)
            server_response = self._transport.recv_frame()
            self._noise.read_message(server_response)
            third = self._noise.write_message(hello.to_bytes())
            self._transport.send_frame(third)
            encrypted_response = self._transport.recv_frame()
            response_bytes = self._noise.decrypt(encrypted_response)
        else:
            self._transport.send_frame(hello.to_bytes())
            response_bytes = self._transport.recv_frame()

        hello_response_cm = self._schema.ControlHelloResponse.from_bytes(response_bytes)
        with _capnp_message(hello_response_cm) as hello_response:
            if not hello_response.accepted:
                raise EventDBXHandshakeError(hello_response.message or "Handshake rejected")

    def _send_request(self, payload_builder: Callable[[Any], None], payload_handler: Callable[[Any], T]) -> T:
        if self._transport is None:
            raise EventDBXConnectionError("Transport is not available")

        self._request_id += 1
        request_id = self._request_id
        request = self._schema.ControlRequest.new_message()
        request.id = request_id
        payload_builder(request.payload)
        response_bytes = self._send_message(request.to_bytes())

        response_cm = self._schema.ControlResponse.from_bytes(response_bytes)
        with _capnp_message(response_cm) as response:
            if response.id != request_id:
                raise EventDBXConnectionError("Mismatched response identifier")

            payload = response.payload
            if payload.which() == "error":
                error = payload.error
                raise EventDBXAPIError(code=error.code, message=error.message)

            return payload_handler(payload)

    def _send_message(self, payload: bytes) -> bytes:
        if self._transport is None:
            raise EventDBXConnectionError("Transport is not available")

        if self._noise is not None:
            ciphertext = self._noise.encrypt(payload)
            self._transport.send_frame(ciphertext)
            return self._noise.decrypt(self._transport.recv_frame())

        self._transport.send_frame(payload)
        return self._transport.recv_frame()
