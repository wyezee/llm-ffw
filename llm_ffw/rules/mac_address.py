"""Deterministic canonical 48-bit MAC-address detection."""

import re

from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from ..mac_address import MACAddressConfig
from .base import Rule, RuleMatch


# Six fixed-width hexadecimal octets with one consistent separator. The
# expression has only fixed bounded repetition, no ambiguous alternation, and
# no attacker-controlled backtracking path.
_MAC_ADDRESS = re.compile(
    r"(?:(?<![A-Za-z0-9_.:-])|(?<=(?i:mac):))"
    r"(?P<address>[0-9A-Fa-f]{2}(?P<separator>[:-])"
    r"(?:[0-9A-Fa-f]{2}(?P=separator)){4}[0-9A-Fa-f]{2})"
    r"(?![A-Za-z0-9_:-]|\.[A-Za-z0-9_-])",
    re.ASCII,
)


class MACAddressRule(Rule):
    """Find canonical 48-bit MAC addresses selected for privacy redaction."""

    RULE_ID = "pii.mac_address"
    PURPOSE = "Detect canonical 48-bit MAC addresses for privacy redaction."
    SCOPES = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))

    def __init__(self, config: MACAddressConfig | None = None) -> None:
        if config is not None and not isinstance(config, MACAddressConfig):
            raise TypeError("config must be a MACAddressConfig or None")
        self._config = config if config is not None else MACAddressConfig()

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
    def config(self) -> MACAddressConfig:
        return self._config

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text
        if ":" not in text and "-" not in text:
            return ()

        matches: list[RuleMatch] = []
        for candidate_count, match in enumerate(
            _MAC_ADDRESS.finditer(text),
            start=1,
        ):
            if candidate_count > self._config.max_candidates:
                matches.append(
                    RuleMatch(
                        span=Span(match.start("address"), len(text)),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message="MAC-address candidate inspection limit exceeded.",
                        metadata={
                            "reason": "candidate_limit_exceeded",
                            "limit": str(self._config.max_candidates),
                            "detector": "bounded_eui_48",
                            "span_basis": "characters",
                        },
                    )
                )
                break

            value = match.group("address")
            first_octet = int(value[:2], 16)
            separator = match.group("separator")
            matches.append(
                RuleMatch(
                    span=Span(*match.span("address")),
                    severity=Severity.MEDIUM,
                    action=Action.REDACT,
                    message="Potentially sensitive MAC address detected.",
                    redacted_preview="[REDACTED:mac_address]",
                    metadata={
                        "reason": "canonical_mac_address",
                        "address_syntax": "eui_48",
                        "separator": (
                            "colon" if separator == ":" else "hyphen"
                        ),
                        "address_kind": (
                            "group" if first_octet & 1 else "individual"
                        ),
                        "administration": (
                            "local" if first_octet & 2 else "universal"
                        ),
                        "detector": "bounded_eui_48",
                        "span_basis": "characters",
                    },
                )
            )
        return tuple(matches)


__all__ = ["MACAddressRule"]
