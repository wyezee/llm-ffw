"""Bounded configuration for deterministic unsafe-URL inspection."""

from dataclasses import dataclass, field
import ipaddress
from itertools import islice
import re
from typing import Iterable

from .inspection import ScanScope


_HARD_MAX_CANDIDATES = 1_024
_HARD_MAX_URL_CHARS = 65_536
_HARD_MAX_HOSTNAME_POLICY_ENTRIES = 1_024
_MAX_HOSTNAME_CHARS = 253
_DNS_LABEL = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z",
    re.ASCII,
)


def _normalize_hostname(value: object, *, allow_ip: bool) -> str:
    if not isinstance(value, str):
        raise TypeError("hostname policy entries must be strings")
    if not value or value != value.strip():
        raise ValueError("hostname policy entries must be non-empty and trimmed")
    if len(value) > _MAX_HOSTNAME_CHARS + 1:
        raise ValueError("hostname policy entry has an invalid length")
    if value.startswith(".") or "*" in value:
        raise ValueError(
            "hostname policy entries must not use leading dots or wildcards"
        )
    if value.endswith(".."):
        raise ValueError("hostname policy entries may have at most one trailing dot")
    if allow_ip:
        try:
            return ipaddress.ip_address(value).compressed.lower()
        except ValueError:
            pass
    else:
        address_value = value[:-1] if value.endswith(".") else value
        try:
            ipaddress.ip_address(address_value)
        except ValueError:
            pass
        else:
            raise ValueError("hostname suffix policy entries must be DNS names")
    try:
        dns_value = value[:-1] if value.endswith(".") else value
        normalized = dns_value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("hostname policy entry is not valid IDNA") from exc
    if not normalized or len(normalized) > _MAX_HOSTNAME_CHARS:
        raise ValueError("hostname policy entry has an invalid length")
    labels = normalized.split(".")
    if any(_DNS_LABEL.fullmatch(label) is None for label in labels):
        raise ValueError("hostname policy entry has an invalid DNS label")
    return normalized


def _normalize_policy_entries(
    value: Iterable[object],
    *,
    allow_ip: bool,
) -> tuple[str, ...]:
    return tuple(
        sorted({_normalize_hostname(entry, allow_ip=allow_ip) for entry in value})
    )


@dataclass(frozen=True, slots=True)
class UnsafeURLConfig:
    """Directions and resource limits for URL candidates."""

    max_candidates: int = 128
    max_url_chars: int = 2_048
    denied_hostnames: tuple[str, ...] = field(default=(), repr=False)
    denied_hostname_suffixes: tuple[str, ...] = field(default=(), repr=False)
    allowed_hostnames: tuple[str, ...] = field(default=(), repr=False)
    allowed_hostname_suffixes: tuple[str, ...] = field(default=(), repr=False)
    scopes: tuple[ScanScope, ...] = (ScanScope.INPUT, ScanScope.OUTPUT)

    def __post_init__(self) -> None:
        for field_name in ("max_candidates", "max_url_chars"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an integer")
            if value <= 0:
                raise ValueError(f"{field_name} must be positive")
        if self.max_candidates > _HARD_MAX_CANDIDATES:
            raise ValueError(f"max_candidates must not exceed {_HARD_MAX_CANDIDATES}")
        if self.max_url_chars > _HARD_MAX_URL_CHARS:
            raise ValueError(f"max_url_chars must not exceed {_HARD_MAX_URL_CHARS}")
        policy_fields = (
            ("denied_hostnames", True),
            ("denied_hostname_suffixes", False),
            ("allowed_hostnames", True),
            ("allowed_hostname_suffixes", False),
        )
        raw_entry_count = 0
        for field_name, allow_ip in policy_fields:
            raw_value = getattr(self, field_name)
            if isinstance(raw_value, (str, bytes)):
                raise TypeError("hostname policy fields must be iterables of strings")
            try:
                remaining = _HARD_MAX_HOSTNAME_POLICY_ENTRIES - raw_entry_count
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
            object.__setattr__(
                self,
                field_name,
                _normalize_policy_entries(
                    raw_entries,
                    allow_ip=allow_ip,
                ),
            )
        if set(self.denied_hostnames) & set(self.allowed_hostnames):
            raise ValueError(
                "the same exact hostname cannot be both allowed and denied"
            )
        if set(self.denied_hostname_suffixes) & set(self.allowed_hostname_suffixes):
            raise ValueError(
                "the same hostname suffix cannot be both allowed and denied"
            )
        if isinstance(self.scopes, (str, bytes)):
            raise TypeError("scopes must be an iterable of ScanScope values")
        try:
            scopes = tuple(self.scopes)
        except TypeError as exc:
            raise TypeError("scopes must be an iterable of ScanScope values") from exc
        if not scopes or any(not isinstance(scope, ScanScope) for scope in scopes):
            raise ValueError("scopes must contain ScanScope values")
        object.__setattr__(
            self,
            "scopes",
            tuple(sorted(set(scopes), key=lambda scope: scope.value)),
        )


__all__ = ["UnsafeURLConfig"]
