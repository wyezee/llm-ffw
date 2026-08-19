"""Bounded configuration for external resource-reference inspection."""

from dataclasses import dataclass, field
from itertools import islice

from .unsafe_url import _normalize_hostname


_HARD_MAX_CANDIDATES = 1_024
_HARD_MAX_MARKUP_CHARS = 65_536
_HARD_MAX_URL_CHARS = 65_536
_HARD_MAX_HOSTNAME_POLICY_ENTRIES = 1_024
_MIN_OPAQUE_SEGMENT_CHARS = 16
_HARD_MAX_OPAQUE_SEGMENT_CHARS = 4_096


@dataclass(frozen=True, slots=True)
class ExternalResourceConfig:
    """Limits and hostname allowlist for output resource references."""

    max_candidates: int = 128
    max_markup_chars: int = 4_096
    max_url_chars: int = 2_048
    opaque_path_segment_chars: int = 64
    allowed_hostnames: tuple[str, ...] = field(default=(), repr=False)
    allowed_hostname_suffixes: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        limits = (
            ("max_candidates", _HARD_MAX_CANDIDATES),
            ("max_markup_chars", _HARD_MAX_MARKUP_CHARS),
            ("max_url_chars", _HARD_MAX_URL_CHARS),
            (
                "opaque_path_segment_chars",
                _HARD_MAX_OPAQUE_SEGMENT_CHARS,
            ),
        )
        for field_name, hard_maximum in limits:
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an integer")
            if value <= 0:
                raise ValueError(f"{field_name} must be positive")
            if value > hard_maximum:
                raise ValueError(
                    f"{field_name} must not exceed {hard_maximum}"
                )
        if self.opaque_path_segment_chars < _MIN_OPAQUE_SEGMENT_CHARS:
            raise ValueError(
                "opaque_path_segment_chars must be at least "
                f"{_MIN_OPAQUE_SEGMENT_CHARS}"
            )

        raw_entry_count = 0
        for field_name, allow_ip in (
            ("allowed_hostnames", True),
            ("allowed_hostname_suffixes", False),
        ):
            raw_value = getattr(self, field_name)
            if isinstance(raw_value, (str, bytes)):
                raise TypeError(
                    "hostname policy fields must be iterables of strings"
                )
            try:
                remaining = (
                    _HARD_MAX_HOSTNAME_POLICY_ENTRIES - raw_entry_count
                )
                raw_entries = tuple(islice(iter(raw_value), remaining + 1))
            except TypeError as exc:
                raise TypeError(
                    "hostname policy fields must be iterables of strings"
                ) from exc
            if len(raw_entries) > remaining:
                raise ValueError(
                    "hostname policy must not exceed "
                    f"{_HARD_MAX_HOSTNAME_POLICY_ENTRIES} entries"
                )
            raw_entry_count += len(raw_entries)
            normalized = tuple(
                sorted(
                    {
                        _normalize_hostname(entry, allow_ip=allow_ip)
                        for entry in raw_entries
                    }
                )
            )
            object.__setattr__(self, field_name, normalized)


__all__ = ["ExternalResourceConfig"]
