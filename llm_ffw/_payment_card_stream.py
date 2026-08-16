"""Internal bounded streaming detector for payment-card candidates."""

from dataclasses import dataclass

from .findings import Action, Finding, Severity, Span
from .rules.payment_card import (
    PaymentCardRule,
    _CARD_CANDIDATE,
    _candidate_properties,
    _passes_luhn,
)


@dataclass(frozen=True, slots=True)
class _PaymentCardDelta:
    safe_through: int
    findings: tuple[Finding, ...]


class _PaymentCardStreamDetector:
    """Finalize bounded card candidates behind a constant source watermark."""

    # Maximum candidate width is 37 characters (19 digits plus 18 optional
    # separators). Two characters of left and right context cover the regex
    # assertions. One extra character keeps the discard boundary conservative.
    HOLD_BACK_CHARS = 42

    __slots__ = (
        "_candidate_count",
        "_findings",
        "_max_candidates",
        "_overflow_start",
        "_pending",
        "_pending_offset",
        "_received_chars",
        "_scan_position",
    )

    def __init__(self, rule: PaymentCardRule) -> None:
        if type(rule) is not PaymentCardRule:
            raise TypeError("rule must be an exact PaymentCardRule")
        self._max_candidates = rule.config.max_candidates
        self._pending = ""
        self._pending_offset = 0
        self._received_chars = 0
        self._scan_position = 0
        self._candidate_count = 0
        self._overflow_start: int | None = None
        self._findings: list[Finding] = []

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(self._findings)

    @property
    def buffered_chars(self) -> int:
        """Return source characters retained for boundary-safe detection."""

        return len(self._pending)

    @property
    def overflow_start(self) -> int | None:
        """Return the fail-closed suffix start after candidate overflow."""

        return self._overflow_start

    def feed(self, chunk: str) -> _PaymentCardDelta:
        if not isinstance(chunk, str):
            raise TypeError("chunk must be a string")
        if not chunk:
            raise ValueError("chunk must not be empty")
        self._pending += chunk
        self._received_chars += len(chunk)
        commit = max(0, len(self._pending) - self.HOLD_BACK_CHARS)
        return self._advance(commit=commit, final=False)

    def finish(self) -> _PaymentCardDelta:
        delta = self._advance(commit=len(self._pending), final=True)
        self._pending = ""
        self._pending_offset = self._received_chars
        return delta

    def cancel(self) -> None:
        self._pending = ""

    def _advance(self, *, commit: int, final: bool) -> _PaymentCardDelta:
        new_findings: list[Finding] = []
        if self._overflow_start is None:
            local_position = max(0, self._scan_position - self._pending_offset)
            for candidate in _CARD_CANDIDATE.finditer(
                self._pending,
                local_position,
            ):
                if not final and candidate.start() >= commit:
                    break
                absolute_start = self._pending_offset + candidate.start()
                absolute_end = self._pending_offset + candidate.end()
                if self._candidate_count >= self._max_candidates:
                    self._overflow_start = absolute_start
                    self._scan_position = absolute_end
                    break
                self._candidate_count += 1
                self._scan_position = absolute_end
                start, end = candidate.span("card")
                properties = _candidate_properties(self._pending, start, end)
                if properties is None or not _passes_luhn(
                    self._pending,
                    start,
                    end,
                ):
                    continue
                digit_count, format_name = properties
                finding = Finding(
                    rule_id=PaymentCardRule.RULE_ID,
                    severity=Severity.HIGH,
                    action=Action.REDACT,
                    span=Span(absolute_start, absolute_end),
                    message="Potential payment-card number detected.",
                    redacted_preview="[REDACTED:payment_card]",
                    metadata={
                        "reason": "luhn_valid_candidate",
                        "detector": "luhn_checksum",
                        "digit_count": str(digit_count),
                        "format": format_name,
                        "span_basis": "characters",
                    },
                )
                self._findings.append(finding)
                new_findings.append(finding)
            self._scan_position = max(
                self._scan_position,
                self._pending_offset + commit,
            )

        safe_through = self._pending_offset + commit
        discard = max(0, commit - 2)
        if discard:
            self._pending = self._pending[discard:]
            self._pending_offset += discard
        if final and self._overflow_start is not None:
            finding = Finding(
                rule_id=PaymentCardRule.RULE_ID,
                severity=Severity.HIGH,
                action=Action.REDACT,
                span=Span(self._overflow_start, self._received_chars),
                message="Payment-card candidate inspection limit exceeded.",
                metadata={
                    "reason": "candidate_limit_exceeded",
                    "limit": str(self._max_candidates),
                    "detector": "luhn_checksum",
                    "span_basis": "characters",
                },
            )
            self._findings.append(finding)
            new_findings.append(finding)
        return _PaymentCardDelta(safe_through, tuple(new_findings))


__all__: list[str] = []
