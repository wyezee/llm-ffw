"""Deterministic findings for deployment-defined banned literals."""

from ..banned_substring_catalog import BannedSubstringCatalog
from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from ..literal_matcher import LiteralDefinition, LiteralMatcher
from .base import Rule, RuleMatch


_MAX_FINDINGS = 64


class BannedSubstringsRule(Rule):
    """Find constrained catalog literals without exposing matched text."""

    RULE_ID = "content.banned_substrings"
    PURPOSE = "Detect deployment-defined banned literal text."

    def __init__(self, catalog: BannedSubstringCatalog) -> None:
        if not isinstance(catalog, BannedSubstringCatalog):
            raise TypeError("catalog must be a BannedSubstringCatalog")
        self._catalog = catalog
        self._patterns = {item.pattern_id: item for item in catalog.patterns}
        self._matcher = LiteralMatcher(
            tuple(
                LiteralDefinition(
                    item.pattern_id,
                    item.value,
                    item.match_mode,
                    item.case_sensitive,
                )
                for item in catalog.patterns
            )
        )

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def purpose(self) -> str:
        return self.PURPOSE

    @property
    def scopes(self) -> frozenset[ScanScope]:
        return frozenset(self._catalog.scopes)

    @property
    def catalog(self) -> BannedSubstringCatalog:
        return self._catalog

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        result = self._matcher.find(inspection.text, max_matches=_MAX_FINDINGS)
        if result.overflow:
            final = result.matches[-1]
            return (
                RuleMatch(
                    span=Span(final.start, final.end),
                    severity=Severity.HIGH,
                    action=Action.BLOCK,
                    message="Banned-substring finding limit exceeded.",
                    metadata={
                        "catalog_id": self._catalog.catalog_id,
                        "catalog_version": self._catalog.version,
                        "detector": "bounded_literal_trie",
                        "limit": str(_MAX_FINDINGS),
                        "span_basis": "characters",
                    },
                ),
            )

        matches: list[RuleMatch] = []
        for item in result.matches:
            pattern = self._patterns[item.pattern_id]
            matches.append(
                RuleMatch(
                    span=Span(item.start, item.end),
                    severity=pattern.severity,
                    action=pattern.action,
                    message="Deployment-defined banned substring detected.",
                    redacted_preview=(
                        "[REDACTED:banned_substring]"
                        if pattern.action is Action.REDACT
                        else None
                    ),
                    metadata={
                        "pattern_id": pattern.pattern_id,
                        "catalog_id": self._catalog.catalog_id,
                        "catalog_version": self._catalog.version,
                        "match_mode": pattern.match_mode.value,
                        "case_sensitive": str(pattern.case_sensitive).lower(),
                        "detector": "bounded_literal_trie",
                        "span_basis": "characters",
                    },
                )
            )
        return tuple(matches)


__all__ = ["BannedSubstringsRule"]
