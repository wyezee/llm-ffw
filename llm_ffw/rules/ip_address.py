"""Deterministic canonical IPv4 and IPv6 detection."""

from collections.abc import Iterator
from dataclasses import dataclass
import ipaddress
import re

from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from ..ip_address import IPAddressConfig
from .base import Rule, RuleMatch


# Four bounded decimal components with identifier boundaries. Validation below
# rejects out-of-range octets and non-canonical leading zeroes. There are no
# nested or attacker-controlled unbounded repetitions.
_IPV4_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?P<address>[0-9]{1,3}(?:\.[0-9]{1,3}){3})"
    r"(?![A-Za-z0-9_-]|\.[A-Za-z0-9_-])",
    re.ASCII,
)
_IPV6_TOKEN_CHARS = frozenset("0123456789abcdefABCDEF:.")
_MAX_IPV6_CHARS = 45


@dataclass(frozen=True, slots=True)
class _AddressCandidate:
    start: int
    end: int
    version: int


def _is_ascii_identifier(character: str) -> bool:
    return (
        "0" <= character <= "9"
        or "A" <= character <= "Z"
        or "a" <= character <= "z"
        or character in "_.-"
    )


def _has_right_identifier_boundary(text: str, end: int) -> bool:
    if end >= len(text):
        return False
    following = text[end]
    if following != ".":
        return _is_ascii_identifier(following)
    return end + 1 < len(text) and (
        text[end + 1].isascii()
        and (text[end + 1].isalnum() or text[end + 1] in "_-")
    )


def _ipv4_candidates(text: str) -> Iterator[_AddressCandidate]:
    for match in _IPV4_CANDIDATE.finditer(text):
        start, end = match.span("address")
        yield _AddressCandidate(start, end, 4)


def _ipv6_candidates(text: str) -> Iterator[_AddressCandidate]:
    position = 0
    text_length = len(text)
    while position < text_length:
        while (
            position < text_length
            and text[position] not in _IPV6_TOKEN_CHARS
        ):
            position += 1
        start = position
        while (
            position < text_length
            and text[position] in _IPV6_TOKEN_CHARS
        ):
            position += 1
        end = position
        while start < end and text[start] == ".":
            start += 1
        while start < end and text[end - 1] == ".":
            end -= 1
        if start < end and text[start] == ":" and not text.startswith("::", start):
            start += 1
        if end <= start or end - start > _MAX_IPV6_CHARS:
            continue
        if start and _is_ascii_identifier(text[start - 1]):
            continue
        if _has_right_identifier_boundary(text, end):
            continue
        candidate = text[start:end]
        colon_count = candidate.count(":")
        if colon_count < 2:
            continue
        if not (
            "::" in candidate
            or colon_count == 7
            or ("." in candidate and colon_count >= 2)
        ):
            continue
        yield _AddressCandidate(start, end, 6)


def _ordered_candidates(
    text: str,
    *,
    include_ipv4: bool,
    include_ipv6: bool,
) -> Iterator[_AddressCandidate]:
    ipv4 = iter(_ipv4_candidates(text)) if include_ipv4 else iter(())
    ipv6 = iter(_ipv6_candidates(text)) if include_ipv6 else iter(())
    next_ipv4 = next(ipv4, None)
    next_ipv6 = next(ipv6, None)
    while next_ipv4 is not None or next_ipv6 is not None:
        if next_ipv4 is None:
            selected = next_ipv6
            next_ipv6 = next(ipv6, None)
        elif next_ipv6 is None:
            selected = next_ipv4
            next_ipv4 = next(ipv4, None)
        elif (next_ipv6.start, -next_ipv6.end) <= (
            next_ipv4.start,
            -next_ipv4.end,
        ):
            selected = next_ipv6
            next_ipv6 = next(ipv6, None)
        else:
            selected = next_ipv4
            next_ipv4 = next(ipv4, None)
        if selected is None:
            break
        yield selected


def _address_class(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    for name, matches in (
        ("unspecified", address.is_unspecified),
        ("loopback", address.is_loopback),
        ("link_local", address.is_link_local),
        ("multicast", address.is_multicast),
        ("private", address.is_private),
        ("global", address.is_global),
        ("reserved", address.is_reserved),
    ):
        if matches:
            return name
    return "other"


class IPAddressRule(Rule):
    """Find canonical IP addresses selected for privacy redaction."""

    RULE_ID = "pii.ip_address"
    PURPOSE = "Detect canonical IPv4 and IPv6 addresses for privacy redaction."
    SCOPES = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))

    def __init__(self, config: IPAddressConfig | None = None) -> None:
        if config is not None and not isinstance(config, IPAddressConfig):
            raise TypeError("config must be an IPAddressConfig or None")
        self._config = config if config is not None else IPAddressConfig()

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def purpose(self) -> str:
        return self.PURPOSE

    @property
    def scopes(self) -> frozenset[ScanScope]:
        return frozenset(self._config.scopes)

    @property
    def config(self) -> IPAddressConfig:
        return self._config

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text
        include_ipv4 = self._config.include_ipv4 and "." in text
        # Every IPv6 candidate accepted below has at least two colons. Find
        # those delimiters in C before entering the character-by-character
        # candidate iterator for large ordinary documents.
        first_colon = text.find(":") if self._config.include_ipv6 else -1
        include_ipv6 = first_colon >= 0 and text.find(":", first_colon + 1) >= 0
        if not include_ipv4 and not include_ipv6:
            return ()

        matches: list[RuleMatch] = []
        candidate_count = 0
        covered_until = 0
        for candidate in _ordered_candidates(
            text,
            include_ipv4=include_ipv4,
            include_ipv6=include_ipv6,
        ):
            if candidate.start < covered_until:
                continue
            if candidate_count >= self._config.max_candidates:
                matches.append(
                    RuleMatch(
                        span=Span(candidate.start, len(text)),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message="IP-address candidate inspection limit exceeded.",
                        metadata={
                            "reason": "candidate_limit_exceeded",
                            "limit": str(self._config.max_candidates),
                            "detector": "stdlib_ipaddress",
                            "span_basis": "characters",
                        },
                    )
                )
                break
            candidate_count += 1
            value = text[candidate.start : candidate.end]
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.version != candidate.version:
                continue
            covered_until = candidate.end
            matches.append(
                RuleMatch(
                    span=Span(candidate.start, candidate.end),
                    severity=Severity.MEDIUM,
                    action=Action.REDACT,
                    message="Potentially sensitive IP address detected.",
                    redacted_preview="[REDACTED:ip_address]",
                    metadata={
                        "reason": "canonical_ip_address",
                        "ip_version": str(address.version),
                        "address_class": _address_class(address),
                        "detector": "stdlib_ipaddress",
                        "span_basis": "characters",
                    },
                )
            )
        return tuple(matches)


__all__ = ["IPAddressRule"]
