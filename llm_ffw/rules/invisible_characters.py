"""Contextual detection of removable invisible Unicode characters."""

import string

from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from .base import Rule, RuleMatch


_ZERO_WIDTH_SPACE = "\u200b"
_ASCII_TOKEN_CHARS = frozenset(string.ascii_letters + string.digits + "._-")
_MAX_REMOVAL_RUNS = 64


class InvisibleCharactersRule(Rule):
    """Find U+200B runs used inside ASCII token-shaped text."""

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

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text
        matches: list[RuleMatch] = []
        search_from = 0
        while True:
            start = text.find(_ZERO_WIDTH_SPACE, search_from)
            if start < 0:
                return tuple(matches)
            end = start + 1
            while end < len(text) and text[end] == _ZERO_WIDTH_SPACE:
                end += 1
            search_from = end
            if (
                start == 0
                or end == len(text)
                or text[start - 1] not in _ASCII_TOKEN_CHARS
                or text[end] not in _ASCII_TOKEN_CHARS
            ):
                continue
            if len(matches) == _MAX_REMOVAL_RUNS:
                return (
                    RuleMatch(
                        span=Span(start, end),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message=(
                            "Invisible-character removal limit exceeded."
                        ),
                        metadata={
                            "character_type": "zero_width_space",
                            "detector": "contextual_ascii_token",
                            "limit": str(_MAX_REMOVAL_RUNS),
                            "span_basis": "characters",
                        },
                    ),
                )
            matches.append(
                RuleMatch(
                    span=Span(start, end),
                    severity=Severity.HIGH,
                    action=Action.REMOVE,
                    message="Invisible character embedded in an ASCII token.",
                    redacted_preview="[REMOVED:invisible_character]",
                    metadata={
                        "character_type": "zero_width_space",
                        "detector": "contextual_ascii_token",
                        "span_basis": "characters",
                    },
                )
            )


__all__ = ["InvisibleCharactersRule"]
