"""Bounded detection of explicit Unicode bidirectional controls."""

from ..findings import Action, Severity, Span
from ..inspection import Inspection, InspectionFeature, ScanScope
from .base import Rule, RuleMatch


_MAX_RUNS_PER_GROUP = 64
_UNICODE_VERSION = "16.0.0"


class BidiControlRule(Rule):
    """Remove directional overrides and review other explicit bidi controls."""

    RULE_ID = "unicode.bidi_controls"
    PURPOSE = "Detect explicit Unicode bidirectional formatting controls."
    SCOPES = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def purpose(self) -> str:
        return self.PURPOSE

    @property
    def scopes(self) -> frozenset[ScanScope]:
        return self.SCOPES

    @property
    def inspection_features(self) -> frozenset[InspectionFeature]:
        return frozenset((InspectionFeature.BIDI_CONTROLS,))

    def _overflow_match(self, span: Span, group: str) -> RuleMatch:
        return RuleMatch(
            span=span,
            severity=Severity.HIGH,
            action=Action.BLOCK,
            message="Bidirectional-control inspection limit exceeded.",
            metadata={
                "control_group": group,
                "detector": "bounded_bidi_control_run",
                "limit": str(_MAX_RUNS_PER_GROUP),
                "span_basis": "characters",
                "unicode_version": _UNICODE_VERSION,
            },
        )

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        candidates = inspection.unicode_security
        if candidates.bidi_override_runs_overflowed:
            return (
                self._overflow_match(
                    candidates.bidi_override_runs[-1],
                    "directional_override",
                ),
            )
        if candidates.bidi_format_runs_overflowed:
            return (
                self._overflow_match(
                    candidates.bidi_format_runs[-1],
                    "explicit_formatting",
                ),
            )

        matches = [
            RuleMatch(
                span=run,
                severity=Severity.HIGH,
                action=Action.REMOVE,
                message="Unicode bidirectional override detected.",
                redacted_preview="[REMOVED:bidi_override]",
                metadata={
                    "control_group": "directional_override",
                    "detector": "bounded_bidi_control_run",
                    "span_basis": "characters",
                    "unicode_version": _UNICODE_VERSION,
                },
            )
            for run in candidates.bidi_override_runs
        ]
        matches.extend(
            RuleMatch(
                span=run,
                severity=Severity.MEDIUM,
                action=Action.REVIEW,
                message="Explicit Unicode bidirectional formatting detected.",
                metadata={
                    "control_group": "explicit_formatting",
                    "detector": "bounded_bidi_control_run",
                    "span_basis": "characters",
                    "unicode_version": _UNICODE_VERSION,
                },
            )
            for run in candidates.bidi_format_runs
        )
        return tuple(
            sorted(
                matches,
                key=lambda match: (match.span.start, match.span.end),
            )
        )


__all__ = ["BidiControlRule"]
