"""Bounded detection of invisible Unicode tag-character payloads."""

from ..findings import Action, Severity, Span
from ..inspection import Inspection, InspectionFeature, ScanScope
from .base import Rule, RuleMatch


_MAX_REMOVAL_RUNS = 64


class UnicodeTagSmugglingRule(Rule):
    """Remove non-RGI Unicode tag runs from model input."""

    RULE_ID = "unicode.tag_smuggling"
    PURPOSE = "Detect invisible Unicode tag runs outside pinned RGI emoji flags."
    SCOPES = frozenset((ScanScope.INPUT,))

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
        return frozenset((InspectionFeature.UNICODE_SECURITY,))

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        candidates = inspection.unicode_security
        if candidates.tag_runs_overflowed:
            run = candidates.tag_runs[-1]
            return (
                RuleMatch(
                    span=Span(run.start, run.end),
                    severity=Severity.HIGH,
                    action=Action.BLOCK,
                    message="Unicode tag removal limit exceeded.",
                    metadata={
                        "character_type": "unicode_tag",
                        "detector": "bounded_tag_run",
                        "limit": str(_MAX_REMOVAL_RUNS),
                        "span_basis": "characters",
                    },
                ),
            )

        matches: list[RuleMatch] = []
        for run in candidates.tag_runs:
            matches.append(
                RuleMatch(
                    span=Span(run.start, run.end),
                    severity=Severity.HIGH,
                    action=Action.REMOVE,
                    message="Invisible Unicode tag sequence detected.",
                    redacted_preview="[REMOVED:unicode_tag_sequence]",
                    metadata={
                        "character_type": "unicode_tag",
                        "detector": "bounded_tag_run",
                        "span_basis": "characters",
                        "unicode_version": "17.0",
                    },
                )
            )
        return tuple(matches)


__all__ = ["UnicodeTagSmugglingRule"]
