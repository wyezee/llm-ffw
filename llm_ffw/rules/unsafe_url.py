"""Deterministic structural checks for unsafe URL candidates."""

from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import urlsplit

from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from ..unsafe_url import (
    UnsafeURLConfig,
    _matches_hostname_suffix,
    _normalize_hostname,
)
from .base import Rule, RuleMatch


# Fixed-width lookbehind, fixed alternatives, and one bounded optional `s`.
# The expression has no ambiguous or attacker-controlled unbounded quantifier.
_URL_START = re.compile(
    r"(?<![A-Za-z0-9+._-])"
    r"(?P<scheme>https?://|javascript:|vbscript:|data:|file:)",
    re.IGNORECASE | re.ASCII,
)
_DANGEROUS_SCHEMES = frozenset(("javascript", "vbscript", "data", "file"))
_CLOUD_METADATA_HOSTNAMES = frozenset(
    ("metadata.google.internal", "metadata.tencentyun.com")
)
_END_DELIMITERS = frozenset(('"', "'", "<", ">", "`"))
_TRAILING_PUNCTUATION = frozenset((".", ",", ";", "!", "?"))
_NUMERIC_HOST = re.compile(
    r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)"
    r"(?:\.(?:0[xX][0-9A-Fa-f]+|[0-9]+)){0,3}\Z",
    re.ASCII,
)
# The numeric-host expression has at most four dot-separated components. Its
# unbounded digit runs are separated by fixed dots and cannot overlap.


@dataclass(frozen=True, slots=True)
class _URLCandidate:
    start: int
    end: int
    scheme: str


def _candidate_end(text: str, start: int) -> int:
    end = start
    delimiter_counts = {
        "(": 0,
        ")": 0,
        "[": 0,
        "]": 0,
        "{": 0,
        "}": 0,
    }
    while end < len(text):
        character = text[end]
        if character.isspace() or character in _END_DELIMITERS:
            break
        if character in delimiter_counts:
            delimiter_counts[character] += 1
        end += 1
    while end > start and text[end - 1] in _TRAILING_PUNCTUATION:
        end -= 1
    for opening, closing in (("(", ")"), ("[", "]"), ("{", "}")):
        while (
            end > start
            and text[end - 1] == closing
            and delimiter_counts[closing] > delimiter_counts[opening]
        ):
            delimiter_counts[closing] -= 1
            end -= 1
    return end


def _find_candidates(
    text: str,
    config: UnsafeURLConfig,
) -> tuple[tuple[_URLCandidate, ...], Span | None]:
    candidates: list[_URLCandidate] = []
    covered_until = 0
    for match in _URL_START.finditer(text):
        # A scheme-like substring inside an undelimited URL candidate is part of
        # that candidate, not a second URL. Skipping it also prevents repeated
        # scans over the same long tail.
        if match.start() < covered_until:
            continue
        if len(candidates) >= config.max_candidates:
            # Policy may safely transform a BLOCK recommendation into REDACT.
            # Cover the uninspected remainder so no candidate can survive it.
            return tuple(candidates), Span(match.start(), len(text))
        end = _candidate_end(text, match.start())
        covered_until = max(covered_until, end)
        if end <= match.end():
            continue
        candidates.append(
            _URLCandidate(
                start=match.start(),
                end=end,
                scheme=match.group("scheme").partition(":")[0].lower(),
            )
        )
    return tuple(candidates), None


def _host_risks(
    candidate: str,
    *,
    denied_hostnames: frozenset[str],
    denied_hostname_suffixes: frozenset[str],
    allowed_hostnames: frozenset[str],
    allowed_hostname_suffixes: frozenset[str],
) -> tuple[str, ...]:
    risks: list[str] = []
    policy_enabled = bool(
        denied_hostnames
        or denied_hostname_suffixes
        or allowed_hostnames
        or allowed_hostname_suffixes
    )
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        # Accessing port forces validation of malformed and out-of-range ports.
        parsed.port
    except ValueError:
        return ("ambiguous_authority",)

    if "\\" in parsed.netloc or "%" in parsed.netloc:
        risks.append("ambiguous_authority")
    if username is not None or password is not None:
        risks.append("embedded_userinfo")
    if hostname is None:
        if policy_enabled:
            risks.append("hostname_policy_unverifiable")
        return tuple(risks)

    lowered = hostname.lower().rstrip(".")
    if lowered == "localhost" or lowered.endswith(".localhost"):
        risks.append("local_hostname")
    if lowered in _CLOUD_METADATA_HOSTNAMES:
        risks.append("cloud_metadata_hostname")

    address_text = lowered
    if "%" in address_text:
        address_text = address_text.partition("%")[0]
    try:
        address = ipaddress.ip_address(address_text)
    except ValueError:
        if _NUMERIC_HOST.fullmatch(address_text):
            risks.append("ambiguous_numeric_host")
    else:
        if not address.is_global or address.is_multicast:
            risks.append("non_public_ip_literal")

    if policy_enabled:
        try:
            policy_hostname = _normalize_hostname(hostname, allow_ip=True)
        except (TypeError, ValueError):
            risks.append("hostname_policy_unverifiable")
        else:
            try:
                ipaddress.ip_address(policy_hostname)
            except ValueError:
                policy_hostname_is_ip = False
            else:
                policy_hostname_is_ip = True
            if policy_hostname in denied_hostnames:
                risks.append("denied_hostname")
            if not policy_hostname_is_ip and _matches_hostname_suffix(
                policy_hostname,
                denied_hostname_suffixes,
            ):
                risks.append("denied_hostname_suffix")
            allowlist_enabled = bool(
                allowed_hostnames or allowed_hostname_suffixes
            )
            allowed = policy_hostname in allowed_hostnames or (
                not policy_hostname_is_ip
                and
                _matches_hostname_suffix(
                    policy_hostname,
                    allowed_hostname_suffixes,
                )
            )
            if allowlist_enabled and not allowed:
                risks.append("hostname_not_allowed")
    return tuple(dict.fromkeys(risks))


class UnsafeURLRule(Rule):
    """Find bounded URL candidates with objective unsafe structure."""

    RULE_ID = "url.unsafe"
    PURPOSE = "Detect URLs with unsafe schemes, authorities, or local targets."
    SCOPES = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))

    def __init__(self, config: UnsafeURLConfig | None = None) -> None:
        if config is not None and not isinstance(config, UnsafeURLConfig):
            raise TypeError("config must be an UnsafeURLConfig or None")
        self._config = config if config is not None else UnsafeURLConfig()
        self._denied_hostnames = frozenset(self._config.denied_hostnames)
        self._denied_hostname_suffixes = frozenset(
            self._config.denied_hostname_suffixes
        )
        self._allowed_hostnames = frozenset(self._config.allowed_hostnames)
        self._allowed_hostname_suffixes = frozenset(
            self._config.allowed_hostname_suffixes
        )

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
    def config(self) -> UnsafeURLConfig:
        return self._config

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text
        candidates, overflow_span = _find_candidates(text, self._config)
        matches: list[RuleMatch] = []
        for candidate in candidates:
            candidate_length = candidate.end - candidate.start
            if candidate_length > self._config.max_url_chars:
                matches.append(
                    RuleMatch(
                        span=Span(candidate.start, candidate.end),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message="URL candidate exceeds the inspection limit.",
                        metadata={
                            "reason": "url_too_long",
                            "limit": str(self._config.max_url_chars),
                            "detector": "bounded_url_structure",
                            "span_basis": "characters",
                        },
                    )
                )
                continue

            risks = (
                ("dangerous_scheme",)
                if candidate.scheme in _DANGEROUS_SCHEMES
                else _host_risks(
                    text[candidate.start : candidate.end],
                    denied_hostnames=self._denied_hostnames,
                    denied_hostname_suffixes=(
                        self._denied_hostname_suffixes
                    ),
                    allowed_hostnames=self._allowed_hostnames,
                    allowed_hostname_suffixes=(
                        self._allowed_hostname_suffixes
                    ),
                )
            )
            if not risks:
                continue
            matches.append(
                RuleMatch(
                    span=Span(candidate.start, candidate.end),
                    severity=Severity.HIGH,
                    action=Action.REDACT,
                    message="Unsafe URL structure detected.",
                    redacted_preview="[REDACTED:unsafe_url]",
                    metadata={
                        "reason": risks[0],
                        "risk_types": ",".join(risks),
                        "scheme": candidate.scheme,
                        "detector": "bounded_url_structure",
                        "span_basis": "characters",
                    },
                )
            )
        if overflow_span is not None:
            matches.append(
                RuleMatch(
                    span=overflow_span,
                    severity=Severity.HIGH,
                    action=Action.BLOCK,
                    message="URL candidate inspection limit exceeded.",
                    metadata={
                        "reason": "candidate_limit_exceeded",
                        "limit": str(self._config.max_candidates),
                        "detector": "bounded_url_structure",
                        "span_basis": "characters",
                    },
                )
            )
        return tuple(matches)


__all__ = ["UnsafeURLRule"]
