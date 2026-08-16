"""Deterministic detection of armored private-key blocks."""

from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from ..private_key import PrivateKeyConfig
from .base import Rule, RuleMatch


_BEGIN_PREFIX = "-----BEGIN "
_FORMATS = (
    ("PRIVATE KEY", "pkcs8"),
    ("ENCRYPTED PRIVATE KEY", "pkcs8_encrypted"),
    ("RSA PRIVATE KEY", "pkcs1_rsa"),
    ("DSA PRIVATE KEY", "dsa"),
    ("EC PRIVATE KEY", "sec1_ec"),
    ("OPENSSH PRIVATE KEY", "openssh"),
    ("PGP PRIVATE KEY BLOCK", "openpgp"),
)
_MARKERS = tuple(
    (
        f"{_BEGIN_PREFIX}{label}-----",
        f"-----END {label}-----",
        format_name,
    )
    for label, format_name in _FORMATS
)


def _failure(
    start: int,
    end: int,
    *,
    reason: str,
    format_name: str,
    config: PrivateKeyConfig,
) -> RuleMatch:
    return RuleMatch(
        span=Span(start, end),
        severity=Severity.HIGH,
        action=Action.BLOCK,
        message="Private-key block could not be safely inspected.",
        metadata={
            "reason": reason,
            "detector": "armor_markers",
            "format": format_name,
            "max_candidates": str(config.max_candidates),
            "max_block_chars": str(config.max_block_chars),
            "span_basis": "characters",
        },
    )


class PrivateKeyRule(Rule):
    """Find bounded PEM, OpenSSH, and OpenPGP private-key blocks."""

    RULE_ID = "secrets.private_key"
    PURPOSE = "Detect armored private-key blocks."
    SCOPES = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))

    def __init__(self, config: PrivateKeyConfig | None = None) -> None:
        if config is not None and not isinstance(config, PrivateKeyConfig):
            raise TypeError("config must be a PrivateKeyConfig or None")
        self._config = config if config is not None else PrivateKeyConfig()

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
    def config(self) -> PrivateKeyConfig:
        return self._config

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text
        if _BEGIN_PREFIX not in text:
            return ()

        matches: list[RuleMatch] = []
        cursor = 0
        candidate_count = 0
        while True:
            start = text.find(_BEGIN_PREFIX, cursor)
            if start < 0:
                break
            selected = next(
                (markers for markers in _MARKERS if text.startswith(markers[0], start)),
                None,
            )
            if selected is None:
                cursor = start + len(_BEGIN_PREFIX)
                continue
            begin_marker, end_marker, format_name = selected
            if candidate_count >= self._config.max_candidates:
                matches.append(
                    _failure(
                        start,
                        len(text),
                        reason="candidate_limit_exceeded",
                        format_name=format_name,
                        config=self._config,
                    )
                )
                break
            candidate_count += 1
            content_start = start + len(begin_marker)
            end_start = text.find(end_marker, content_start)
            if end_start < 0:
                reason = (
                    "block_size_exceeded"
                    if len(text) - start > self._config.max_block_chars
                    else "missing_end_marker"
                )
                matches.append(
                    _failure(
                        start,
                        len(text),
                        reason=reason,
                        format_name=format_name,
                        config=self._config,
                    )
                )
                break
            end = end_start + len(end_marker)
            if end - start > self._config.max_block_chars:
                matches.append(
                    _failure(
                        start,
                        len(text),
                        reason="block_size_exceeded",
                        format_name=format_name,
                        config=self._config,
                    )
                )
                break
            matches.append(
                RuleMatch(
                    span=Span(start, end),
                    severity=Severity.HIGH,
                    action=Action.REDACT,
                    message="Potential private-key block detected.",
                    redacted_preview="[REDACTED:private_key]",
                    metadata={
                        "reason": "complete_armored_block",
                        "detector": "armor_markers",
                        "format": format_name,
                        "span_basis": "characters",
                    },
                )
            )
            cursor = end
        return tuple(matches)


__all__ = ["PrivateKeyRule"]
