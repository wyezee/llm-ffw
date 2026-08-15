"""Immutable policy catalogs for deterministic banned-literal matching."""

from dataclasses import dataclass
import re

from .findings import Action, Severity
from .inspection import ScanScope
from .literal_matcher import LiteralDefinition, LiteralMatchMode, LiteralMatcher


_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?\Z")
_VERSION = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.+_-]{0,62}[A-Za-z0-9])?\Z")


@dataclass(frozen=True, slots=True)
class BannedSubstring:
    """One constrained literal and its recommended finding handling."""

    pattern_id: str
    value: str
    match_mode: LiteralMatchMode = LiteralMatchMode.SUBSTRING
    case_sensitive: bool = False
    severity: Severity = Severity.HIGH
    action: Action = Action.REDACT

    def __post_init__(self) -> None:
        LiteralDefinition(
            self.pattern_id,
            self.value,
            self.match_mode,
            self.case_sensitive,
        )
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity")
        if not isinstance(self.action, Action):
            raise TypeError("action must be an Action")


@dataclass(frozen=True, slots=True)
class BannedSubstringCatalog:
    """Versioned in-memory literals with explicit input/output scopes."""

    catalog_id: str
    version: str
    patterns: tuple[BannedSubstring, ...]
    scopes: tuple[ScanScope, ...] = (ScanScope.INPUT, ScanScope.OUTPUT)

    def __post_init__(self) -> None:
        if not isinstance(self.catalog_id, str) or not _IDENTIFIER.fullmatch(
            self.catalog_id
        ):
            raise ValueError("catalog_id must be a stable lowercase identifier")
        if not isinstance(self.version, str) or not _VERSION.fullmatch(self.version):
            raise ValueError("version must be a stable identifier")
        if isinstance(self.patterns, (str, bytes)):
            raise TypeError("patterns must contain BannedSubstring values")
        try:
            patterns = tuple(self.patterns)
        except TypeError as exc:
            raise TypeError(
                "patterns must contain BannedSubstring values"
            ) from exc
        if any(not isinstance(item, BannedSubstring) for item in patterns):
            raise TypeError("patterns must contain BannedSubstring values")
        LiteralMatcher(
            tuple(
                LiteralDefinition(
                    item.pattern_id,
                    item.value,
                    item.match_mode,
                    item.case_sensitive,
                )
                for item in patterns
            )
        )
        try:
            scopes = tuple(self.scopes)
        except TypeError as exc:
            raise TypeError("scopes must contain ScanScope values") from exc
        if not scopes or any(not isinstance(item, ScanScope) for item in scopes):
            raise ValueError("scopes must contain ScanScope values")
        object.__setattr__(self, "patterns", patterns)
        object.__setattr__(
            self,
            "scopes",
            tuple(sorted(set(scopes), key=lambda item: item.value)),
        )


__all__ = ["BannedSubstring", "BannedSubstringCatalog", "LiteralMatchMode"]
