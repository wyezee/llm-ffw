"""Bounded multi-pattern matching for constrained printable-ASCII literals."""

from dataclasses import dataclass
from enum import Enum
import re
import string


_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?\Z")
_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_MAX_PATTERNS = 1_024
_MIN_LITERAL_LENGTH = 3
_MAX_LITERAL_LENGTH = 64
_MAX_TOTAL_LITERAL_CHARACTERS = 65_536


class LiteralMatchMode(str, Enum):
    """Supported deterministic literal boundary semantics."""

    SUBSTRING = "substring"
    ASCII_WORD = "ascii_word"


@dataclass(frozen=True, slots=True)
class LiteralDefinition:
    """One validated literal without executable matching syntax."""

    pattern_id: str
    value: str
    match_mode: LiteralMatchMode = LiteralMatchMode.SUBSTRING
    case_sensitive: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.pattern_id, str) or not _IDENTIFIER.fullmatch(
            self.pattern_id
        ):
            raise ValueError("pattern_id must be a stable lowercase identifier")
        if not isinstance(self.value, str) or not (
            _MIN_LITERAL_LENGTH <= len(self.value) <= _MAX_LITERAL_LENGTH
        ):
            raise ValueError("value length must be between 3 and 64 characters")
        if not self.value.isascii() or not self.value.isprintable():
            raise ValueError("value must contain printable ASCII only")
        if not isinstance(self.match_mode, LiteralMatchMode):
            raise TypeError("match_mode must be a LiteralMatchMode")
        if not isinstance(self.case_sensitive, bool):
            raise TypeError("case_sensitive must be a boolean")


@dataclass(frozen=True, order=True, slots=True)
class LiteralMatch:
    """A matched pattern identity and half-open character span."""

    start: int
    end: int
    pattern_id: str

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError("literal match span must be non-empty")
        if not isinstance(self.pattern_id, str) or not self.pattern_id:
            raise ValueError("pattern_id must be non-empty")


@dataclass(frozen=True, slots=True)
class LiteralMatchResult:
    """Bounded matches plus an explicit overflow signal."""

    matches: tuple[LiteralMatch, ...]
    overflow: bool


class _RegexTrieNode:
    __slots__ = ("children", "terminal")

    def __init__(self) -> None:
        self.children: dict[str, _RegexTrieNode] = {}
        self.terminal = False


def _emit_regex_trie(node: _RegexTrieNode) -> str:
    alternatives = [
        re.escape(character) + _emit_regex_trie(child)
        for character, child in sorted(node.children.items())
    ]
    if node.terminal:
        alternatives.append("")
    if len(alternatives) == 1:
        return alternatives[0]
    return "(?:" + "|".join(alternatives) + ")"


def _compile_group(
    definitions: tuple[LiteralDefinition, ...],
    *,
    case_sensitive: bool,
    match_mode: LiteralMatchMode,
) -> re.Pattern[str]:
    root = _RegexTrieNode()
    for definition in definitions:
        node = root
        for character in definition.value:
            node = node.children.setdefault(character, _RegexTrieNode())
        node.terminal = True
    expression = _emit_regex_trie(root)
    if match_mode is LiteralMatchMode.ASCII_WORD:
        expression = (
            r"(?<![A-Za-z0-9_])(?:"
            + expression
            + r")(?![A-Za-z0-9_])"
        )
    flags = re.ASCII | (0 if case_sensitive else re.IGNORECASE)
    return re.compile(expression, flags)


def _ascii_lower(value: str) -> str:
    return value.translate(_ASCII_LOWER)


class LiteralMatcher:
    """Compile validated literals once and return bounded deterministic spans."""

    def __init__(self, definitions: tuple[LiteralDefinition, ...]) -> None:
        if isinstance(definitions, (str, bytes)):
            raise TypeError("definitions must contain LiteralDefinition values")
        try:
            selected = tuple(definitions)
        except TypeError as exc:
            raise TypeError(
                "definitions must contain LiteralDefinition values"
            ) from exc
        if not selected or len(selected) > _MAX_PATTERNS:
            raise ValueError("definitions must contain between 1 and 1024 values")
        if any(not isinstance(item, LiteralDefinition) for item in selected):
            raise TypeError("definitions must contain LiteralDefinition values")
        if sum(len(item.value) for item in selected) > _MAX_TOTAL_LITERAL_CHARACTERS:
            raise ValueError("total literal characters must not exceed 65536")
        if len({item.pattern_id for item in selected}) != len(selected):
            raise ValueError("pattern_id values must be unique")
        comparable = [_ascii_lower(item.value) for item in selected]
        if len(set(comparable)) != len(comparable):
            raise ValueError("literal values must be unique ignoring ASCII case")

        groups: list[
            tuple[re.Pattern[str], bool, dict[str, str]]
        ] = []
        for case_sensitive in (True, False):
            for match_mode in LiteralMatchMode:
                members = tuple(
                    item
                    for item in selected
                    if item.case_sensitive is case_sensitive
                    and item.match_mode is match_mode
                )
                if not members:
                    continue
                expression = _compile_group(
                    members,
                    case_sensitive=case_sensitive,
                    match_mode=match_mode,
                )
                identities = {
                    item.value if case_sensitive else _ascii_lower(item.value): item.pattern_id
                    for item in members
                }
                groups.append((expression, case_sensitive, identities))
        self._groups = tuple(groups)
        self._definitions = selected

    @property
    def definitions(self) -> tuple[LiteralDefinition, ...]:
        return self._definitions

    def find(self, text: str, *, max_matches: int) -> LiteralMatchResult:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if isinstance(max_matches, bool) or not isinstance(max_matches, int):
            raise TypeError("max_matches must be an integer")
        if max_matches <= 0:
            raise ValueError("max_matches must be positive")

        # One selected 64-character interval can cover at most 22 disjoint
        # three-character raw matches from another group. This cap therefore
        # proves overflow without collecting attacker-controlled match counts.
        raw_limit = max_matches * (
            (_MAX_LITERAL_LENGTH + _MIN_LITERAL_LENGTH - 1)
            // _MIN_LITERAL_LENGTH
        ) + 1
        candidates: list[LiteralMatch] = []
        raw_overflow = False
        for expression, case_sensitive, identities in self._groups:
            count = 0
            for match in expression.finditer(text):
                count += 1
                if count > raw_limit:
                    raw_overflow = True
                    break
                value = match.group(0)
                comparable = value if case_sensitive else _ascii_lower(value)
                candidates.append(
                    LiteralMatch(
                        match.start(),
                        match.end(),
                        identities[comparable],
                    )
                )

        ordered = sorted(
            candidates,
            key=lambda item: (
                item.start,
                -(item.end - item.start),
                item.pattern_id,
            ),
        )
        selected_matches: list[LiteralMatch] = []
        cursor = 0
        for item in ordered:
            if item.start < cursor:
                continue
            selected_matches.append(item)
            cursor = item.end
            if len(selected_matches) > max_matches:
                return LiteralMatchResult(
                    matches=tuple(selected_matches[:max_matches]),
                    overflow=True,
                )
        return LiteralMatchResult(
            matches=tuple(selected_matches),
            overflow=raw_overflow,
        )


__all__ = [
    "LiteralDefinition",
    "LiteralMatch",
    "LiteralMatcher",
    "LiteralMatchMode",
    "LiteralMatchResult",
]
