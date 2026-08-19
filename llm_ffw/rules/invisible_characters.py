"""Contextual detection of removable invisible Unicode characters."""

from ..findings import Action, Severity, Span
from ..inspection import Inspection, InspectionFeature, ScanScope
from .base import Rule, RuleMatch


_MAX_REMOVAL_RUNS = 64
_CHARACTER_TYPES = {
    "\u200b": "zero_width_space",
    "\u200c": "zero_width_non_joiner",
    "\u200d": "zero_width_joiner",
    "\u2060": "word_joiner",
    "\ufeff": "zero_width_no_break_space",
}


def _character_type(value: str) -> str:
    types = {_CHARACTER_TYPES[character] for character in value}
    if len(types) == 1:
        return types.pop()
    return "mixed_contextual_invisible"


class InvisibleCharactersRule(Rule):
    """Find selected invisible-character runs inside ASCII token text."""

    RULE_ID = "unicode.invisible_characters"
    PURPOSE = "Detect removable invisible characters embedded in ASCII tokens."
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
        if candidates.contextual_invisible_runs_overflowed:
            run = candidates.contextual_invisible_runs[-1]
            return (
                RuleMatch(
                    span=Span(run.start, run.end),
                    severity=Severity.HIGH,
                    action=Action.BLOCK,
                    message="Invisible-character removal limit exceeded.",
                    metadata={
                        "character_type": _character_type(
                            inspection.text[run.start : run.end]
                        ),
                        "detector": "contextual_ascii_token",
                        "limit": str(_MAX_REMOVAL_RUNS),
                        "span_basis": "characters",
                    },
                ),
            )
        matches: list[RuleMatch] = []
        for run in candidates.contextual_invisible_runs:
            start, end = run.start, run.end
            matches.append(
                RuleMatch(
                    span=Span(start, end),
                    severity=Severity.HIGH,
                    action=Action.REMOVE,
                    message="Invisible character embedded in an ASCII token.",
                    redacted_preview="[REMOVED:invisible_character]",
                    metadata={
                        "character_type": _character_type(
                            inspection.text[start:end]
                        ),
                        "detector": "contextual_ascii_token",
                        "span_basis": "characters",
                    },
                )
            )
        return tuple(matches)


__all__ = ["InvisibleCharactersRule"]
