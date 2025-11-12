"""EventDBX Python client package."""

__version__ = "0.1.2"

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
    SelectAggregateResult,
)
from .control_schema import build_control_hello, load_control_schema
from .noise import DEFAULT_NOISE_PROLOGUE, DEFAULT_NOISE_PROTOCOL, NoiseSession

__all__ = [
    "EventDBXClient",
    "EventDBXAPIError",
    "EventDBXHandshakeError",
    "EventDBXConnectionError",
    "NoiseSession",
    "DEFAULT_NOISE_PROTOCOL",
    "DEFAULT_NOISE_PROLOGUE",
    "build_control_hello",
    "load_control_schema",
    "ListEventsResult",
    "ListAggregatesResult",
    "GetAggregateResult",
    "SelectAggregateResult",
    "AggregateSortField",
    "AggregateSortOption",
    "__version__",
]
