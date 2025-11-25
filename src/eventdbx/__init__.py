"""EventDBX Python client package."""

__version__ = "0.1.8"

from .client import (
    AggregateSortField,
    AggregateSortOption,
    EventDBXAPIError,
    EventDBXClient,
    EventDBXConnectionError,
    EventDBXHandshakeError,
    GetAggregateResult,
    ListAggregatesResult,
    ListEventsResult,
    ListSnapshotsResult,
    GetSnapshotResult,
    PublishTarget,
    RetryOptions,
    SelectAggregateResult,
    TenantAssignResult,
    TenantQuotaResult,
    TenantSchemaPublishResult,
)
from .control_schema import build_control_hello, load_control_schema
from .noise import DEFAULT_NOISE_PROLOGUE, DEFAULT_NOISE_PROTOCOL, NoiseSession, derive_psk

__all__ = [
    "EventDBXClient",
    "EventDBXAPIError",
    "EventDBXHandshakeError",
    "EventDBXConnectionError",
    "NoiseSession",
    "DEFAULT_NOISE_PROTOCOL",
    "DEFAULT_NOISE_PROLOGUE",
    "derive_psk",
    "build_control_hello",
    "load_control_schema",
    "ListEventsResult",
    "ListAggregatesResult",
    "GetAggregateResult",
    "ListSnapshotsResult",
    "GetSnapshotResult",
    "PublishTarget",
    "SelectAggregateResult",
    "TenantAssignResult",
    "TenantQuotaResult",
    "TenantSchemaPublishResult",
    "AggregateSortField",
    "AggregateSortOption",
    "RetryOptions",
    "__version__",
]
