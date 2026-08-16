"""Stable public value types for unified firewall streaming."""

from dataclasses import dataclass
from enum import Enum


class StreamMode(str, Enum):
    """Requested or resolved stream execution strategy."""

    AUTO = "auto"
    INCREMENTAL = "incremental"
    BUFFERED = "buffered"


class StreamingSupport(str, Enum):
    """Current streaming support for one active rule."""

    INCREMENTAL = "incremental"
    END_OF_STREAM = "end_of_stream"


class FirewallStreamState(str, Enum):
    """Lifecycle state of a firewall stream."""

    OPEN = "open"
    FINISHED = "finished"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class StreamingRuleCapability:
    """Disclosure-safe streaming support metadata for one active rule."""

    rule_id: str
    support: StreamingSupport
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not self.rule_id:
            raise ValueError("rule_id must be a non-empty string")
        if not isinstance(self.support, StreamingSupport):
            raise TypeError("support must be a StreamingSupport")
        if not isinstance(self.reason, str) or not self.reason:
            raise ValueError("reason must be a non-empty string")


class IncrementalStreamingUnavailableError(ValueError):
    """Raised when explicit incremental execution cannot preserve semantics."""

    def __init__(self, incompatibilities: tuple[str, ...]) -> None:
        if not incompatibilities or any(
            not isinstance(item, str) or not item
            for item in incompatibilities
        ):
            raise ValueError("incompatibilities must contain non-empty strings")
        normalized = tuple(sorted(set(incompatibilities)))
        super().__init__(
            "incremental streaming is unavailable for configuration: "
            + ", ".join(normalized)
        )
        self.incompatibilities = normalized


__all__ = [
    "FirewallStreamState",
    "IncrementalStreamingUnavailableError",
    "StreamingRuleCapability",
    "StreamingSupport",
    "StreamMode",
]
