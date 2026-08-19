"""Deterministic excessive character, token, and line repetition detection."""

from collections.abc import Iterator
from dataclasses import dataclass
from itertools import islice
import re

from ..findings import Action, Severity, Span
from ..inspection import Inspection, InspectionFeature, ScanScope
from ..repetition import RepetitionConfig
from .base import Rule, RuleMatch


_MAX_TRACKED_TOKEN_CHARS = 128
_MAX_TRACKED_LINE_CHARS = 4_096
_MAX_SPLIT_LINES = 1_000_000
_MAX_SPLIT_SEPARATORS = 1_500_000
_OTHER_LINE_SEPARATORS = "\v\f\x1c\x1d\x1e\x85\u2028\u2029"
_LINE_SEPARATOR = re.compile(f"[\n{_OTHER_LINE_SEPARATORS}]")
_OTHER_LINE_SEPARATOR = re.compile(f"[{_OTHER_LINE_SEPARATORS}]")


@dataclass(frozen=True, slots=True)
class _Repeat:
    start: int
    end: int
    reason: str
    count: int
    unit_length: int


def _character_repeats(
    text: str,
    threshold: int,
    limit: int,
    ascii_characters: tuple[str, ...] | None,
) -> Iterator[_Repeat]:
    if ascii_characters is not None:
        candidates: list[_Repeat] = []
        text_length = len(text)
        for character in ascii_characters:
            if character.isspace():
                continue
            needle = character * threshold
            position = 0
            character_count = 0
            while character_count < limit:
                start = text.find(needle, position)
                if start < 0:
                    break
                end = start + threshold
                while end + threshold <= text_length and text.startswith(
                    needle, end
                ):
                    end += threshold
                while end < text_length and text[end] == character:
                    end += 1
                candidates.append(
                    _Repeat(start, end, "character_run", end - start, 1)
                )
                character_count += 1
                position = end
        candidates.sort(key=lambda item: item.start)
        yield from islice(candidates, limit)
        return
    start = 0
    while start < len(text):
        character = text[start]
        end = start + 1
        while end < len(text) and text[end] == character:
            end += 1
        count = end - start
        if not character.isspace() and count >= threshold:
            yield _Repeat(start, end, "character_run", count, 1)
        start = end


def _many_token_repeats(text: str, threshold: int) -> Iterator[_Repeat]:
    position = 0
    previous: str | None = None
    run_start = 0
    run_end = 0
    count = 0
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        start = position
        has_alnum = False
        while position < len(text) and not text[position].isspace():
            has_alnum = has_alnum or text[position].isalnum()
            position += 1
        end = position
        length = end - start
        token = (
            text[start:end]
            if has_alnum and 0 < length <= _MAX_TRACKED_TOKEN_CHARS
            else None
        )
        if token is not None and token == previous:
            count += 1
            run_end = end
        else:
            if previous is not None and count >= threshold:
                yield _Repeat(
                    run_start, run_end, "token_run", count, len(previous)
                )
            previous = token
            run_start = start
            run_end = end
            count = 1 if token is not None else 0
    if previous is not None and count >= threshold:
        yield _Repeat(run_start, run_end, "token_run", count, len(previous))


def _contains_alphanumeric(value: str) -> bool:
    """Return whether a bounded token contains an alphanumeric character."""

    # Ordinary tokens usually begin or end with an alphanumeric character.
    # Preserve the exact Unicode-aware fallback for punctuation-wrapped tokens.
    if value[0].isalnum() or value[-1].isalnum():
        return True
    return any(character.isalnum() for character in value[1:-1])


def _token_repeats(
    text: str, threshold: int, limit: int, *, is_ascii: bool
) -> Iterator[_Repeat]:
    if re.search(r"\s", text) is None or re.search(r"\w", text) is None:
        return
    if not is_ascii or sum(
        text.count(character) for character in " \t\n\r\v\f"
    ) > _MAX_SPLIT_SEPARATORS:
        yield from _many_token_repeats(text, threshold)
        return
    tokens = text.split()
    previous: str | None = None
    run_start_index = 0
    count = 0
    runs: list[tuple[int, int, str]] = []
    for index, value in enumerate(tokens):
        token = value if len(value) <= _MAX_TRACKED_TOKEN_CHARS else None
        if token is not None and not _contains_alphanumeric(token):
            token = None
        if token is not None and token == previous:
            count += 1
        else:
            if previous is not None and count >= threshold:
                runs.append((run_start_index, index, previous))
                if len(runs) >= limit:
                    break
            previous = token
            run_start_index = index
            count = 1 if token is not None else 0
    if (
        len(runs) < limit
        and previous is not None
        and count >= threshold
    ):
        runs.append((run_start_index, len(tokens), previous))
    if not runs:
        return

    run_index = 0
    active = runs[run_index]
    start = 0
    for index, match in enumerate(re.finditer(r"\S+", text)):
        if index == active[0]:
            start = match.start()
        if index + 1 == active[1]:
            yield _Repeat(
                start,
                match.end(),
                "token_run",
                active[1] - active[0],
                len(active[2]),
            )
            run_index += 1
            if run_index == len(runs):
                return
            active = runs[run_index]


def _line_segments(text: str) -> Iterator[tuple[int, int]]:
    position = 0
    for separator in _LINE_SEPARATOR.finditer(text):
        yield position, separator.start()
        position = separator.end()
    yield position, len(text)


def _many_line_repeats(text: str, threshold: int) -> Iterator[_Repeat]:
    if _LINE_SEPARATOR.search(text) is None:
        return
    previous: str | None = None
    run_start = 0
    run_end = 0
    count = 0
    for position, content_end in _line_segments(text):
        length = content_end - position
        line = (
            text[position:content_end]
            if 0 < length <= _MAX_TRACKED_LINE_CHARS
            else None
        )
        if line is not None and line.isspace():
            line = None
        if line is not None and line == previous:
            count += 1
            run_end = content_end
        else:
            if previous is not None and count >= threshold:
                yield _Repeat(
                    run_start, run_end, "line_run", count, len(previous)
                )
            previous = line
            run_start = position
            run_end = content_end
            count = 1 if line is not None else 0
    if previous is not None and count >= threshold:
        yield _Repeat(run_start, run_end, "line_run", count, len(previous))


def _line_repeats(text: str, threshold: int) -> Iterator[_Repeat]:
    newline_count = text.count("\n")
    has_other_separator = _OTHER_LINE_SEPARATOR.search(text) is not None
    if newline_count == 0 and not has_other_separator:
        return
    separator_count = newline_count
    if has_other_separator:
        separator_count += sum(
            text.count(separator) for separator in _OTHER_LINE_SEPARATORS
        )
    if separator_count > _MAX_SPLIT_LINES:
        yield from _many_line_repeats(text, threshold)
        return
    lines = text.splitlines(keepends=True)
    previous: str | None = None
    run_start = 0
    run_end = 0
    count = 0
    offset = 0
    for raw_line in lines:
        content_end = len(raw_line)
        if content_end and raw_line[-1] in "\n" + _OTHER_LINE_SEPARATORS:
            content_end -= 1
        if content_end and raw_line[content_end - 1] == "\r":
            content_end -= 1
        line = (
            raw_line[:content_end]
            if 0 < content_end <= _MAX_TRACKED_LINE_CHARS
            else None
        )
        if line is not None and line.isspace():
            line = None
        if line is not None and line == previous:
            count += 1
            run_end = offset + content_end
        else:
            if previous is not None and count >= threshold:
                yield _Repeat(
                    run_start, run_end, "line_run", count, len(previous)
                )
            previous = line
            run_start = offset
            run_end = offset + content_end
            count = 1 if line is not None else 0
        offset += len(raw_line)
    if previous is not None and count >= threshold:
        yield _Repeat(
            run_start,
            run_end,
            "line_run",
            count,
            len(previous),
        )


class RepetitionRule(Rule):
    """Report conservative, exact excessive-repetition signals."""

    RULE_ID = "text.excessive_repetition"
    PURPOSE = (
        "Detect excessive exact character, token, and non-empty line repetition."
    )
    SCOPES = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))

    def __init__(self, config: RepetitionConfig | None = None) -> None:
        if config is not None and not isinstance(config, RepetitionConfig):
            raise TypeError("config must be a RepetitionConfig or None")
        self._config = config or RepetitionConfig()

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
    def config(self) -> RepetitionConfig:
        return self._config

    @property
    def inspection_features(self) -> frozenset[InspectionFeature]:
        return frozenset((InspectionFeature.ASCII,))

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text
        is_ascii = inspection.is_ascii
        inspection_limit = self._config.max_findings + 1
        repeats: list[_Repeat] = []
        ascii_characters = tuple(sorted(set(text))) if is_ascii else None
        if ascii_characters is not None and len(ascii_characters) == 1:
            character = ascii_characters[0]
            if (
                not character.isspace()
                and len(text) >= self._config.character_run_threshold
            ):
                repeats.append(
                    _Repeat(0, len(text), "character_run", len(text), 1)
                )
        else:
            for detector in (
                _character_repeats(
                    text,
                    self._config.character_run_threshold,
                    inspection_limit,
                    ascii_characters,
                ),
                _token_repeats(
                    text,
                    self._config.token_repeat_threshold,
                    inspection_limit,
                    is_ascii=is_ascii,
                ),
                _line_repeats(text, self._config.line_repeat_threshold),
            ):
                repeats.extend(islice(detector, inspection_limit))
        repeats.sort(key=lambda item: (item.start, item.end, item.reason))
        matches: list[RuleMatch] = []
        for repeat in repeats:
            if len(matches) >= self._config.max_findings:
                matches.append(
                    RuleMatch(
                        span=Span(repeat.start, len(text)),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message="Repetition finding limit exceeded.",
                        metadata={
                            "reason": "finding_limit_exceeded",
                            "limit": str(self._config.max_findings),
                            "detector": "bounded_exact_repetition",
                            "span_basis": "characters",
                        },
                    )
                )
                break
            matches.append(
                RuleMatch(
                    span=Span(repeat.start, repeat.end),
                    severity=Severity.MEDIUM,
                    action=Action.REVIEW,
                    message="Excessive exact repetition detected.",
                    metadata={
                        "reason": repeat.reason,
                        "repeat_count": str(repeat.count),
                        "unit_length": str(repeat.unit_length),
                        "detector": "bounded_exact_repetition",
                        "span_basis": "characters",
                    },
                )
            )
        return tuple(matches)


__all__ = ["RepetitionRule"]
