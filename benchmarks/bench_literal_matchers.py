"""Compare bounded standard-library literal multi-pattern strategies."""

import argparse
from collections import deque
from dataclasses import dataclass
from pathlib import Path
import re
from statistics import median
import string
import sys
import time
import tracemalloc
from typing import Protocol

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm_ffw.literal_matcher import (
    LiteralDefinition as RuntimeLiteralDefinition,
    LiteralMatcher as RuntimeLiteralMatcher,
)


_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_ASCII_WORD = frozenset(string.ascii_letters + string.digits + "_")


@dataclass(frozen=True, slots=True)
class LiteralPattern:
    pattern_id: str
    value: str


@dataclass(frozen=True, order=True, slots=True)
class LiteralSpan:
    start: int
    end: int
    pattern_id: str


class Matcher(Protocol):
    def find(self, text: str, *, word_boundary: bool = False) -> tuple[LiteralSpan, ...]: ...


def _ascii_lower(value: str) -> str:
    return value.translate(_ASCII_LOWER)


def _validate_patterns(
    patterns: tuple[LiteralPattern, ...],
    *,
    case_sensitive: bool,
) -> tuple[LiteralPattern, ...]:
    if not patterns or len(patterns) > 1_024:
        raise ValueError("patterns must contain between 1 and 1024 values")
    if sum(len(item.value) for item in patterns) > 65_536:
        raise ValueError("total literal characters must not exceed 65536")
    ids: set[str] = set()
    values: set[str] = set()
    for item in patterns:
        if not isinstance(item, LiteralPattern):
            raise TypeError("patterns must contain LiteralPattern values")
        if not item.pattern_id or item.pattern_id in ids:
            raise ValueError("pattern IDs must be non-empty and unique")
        if not 3 <= len(item.value) <= 64:
            raise ValueError("literal length must be between 3 and 64")
        if not item.value.isascii() or not item.value.isprintable():
            raise ValueError("literals must be printable ASCII")
        comparable = item.value if case_sensitive else _ascii_lower(item.value)
        if comparable in values:
            raise ValueError("literal values must be unique for the selected mode")
        ids.add(item.pattern_id)
        values.add(comparable)
    return patterns


def _has_ascii_word_boundaries(text: str, start: int, end: int) -> bool:
    return (
        (start == 0 or text[start - 1] not in _ASCII_WORD)
        and (end == len(text) or text[end] not in _ASCII_WORD)
    )


def _resolve(matches: list[LiteralSpan]) -> tuple[LiteralSpan, ...]:
    ordered = sorted(
        matches,
        key=lambda item: (
            item.start,
            -(item.end - item.start),
            item.pattern_id,
        ),
    )
    selected: list[LiteralSpan] = []
    cursor = 0
    for item in ordered:
        if item.start < cursor:
            continue
        selected.append(item)
        cursor = item.end
    return tuple(selected)


class SequentialFindMatcher:
    def __init__(
        self,
        patterns: tuple[LiteralPattern, ...],
        *,
        case_sensitive: bool,
    ) -> None:
        selected = _validate_patterns(patterns, case_sensitive=case_sensitive)
        self._case_sensitive = case_sensitive
        self._patterns = tuple(
            (
                item.pattern_id,
                item.value if case_sensitive else _ascii_lower(item.value),
            )
            for item in selected
        )

    def find(
        self,
        text: str,
        *,
        word_boundary: bool = False,
    ) -> tuple[LiteralSpan, ...]:
        searched = text if self._case_sensitive else _ascii_lower(text)
        matches: list[LiteralSpan] = []
        for pattern_id, value in self._patterns:
            start = 0
            while True:
                start = searched.find(value, start)
                if start < 0:
                    break
                end = start + len(value)
                if not word_boundary or _has_ascii_word_boundaries(text, start, end):
                    matches.append(LiteralSpan(start, end, pattern_id))
                start += 1
        return _resolve(matches)


class RegexAlternationMatcher:
    @staticmethod
    def _expression(patterns: tuple[LiteralPattern, ...]) -> str:
        ordered = sorted(
            patterns,
            key=lambda item: (-len(item.value), item.pattern_id),
        )
        return "|".join(re.escape(item.value) for item in ordered)

    def __init__(
        self,
        patterns: tuple[LiteralPattern, ...],
        *,
        case_sensitive: bool,
    ) -> None:
        selected = _validate_patterns(patterns, case_sensitive=case_sensitive)
        flags = re.ASCII | (0 if case_sensitive else re.IGNORECASE)
        alternatives = self._expression(selected)
        self._substring = re.compile(f"(?:{alternatives})", flags)
        self._word = re.compile(
            f"(?<![A-Za-z0-9_])(?:{alternatives})(?![A-Za-z0-9_])",
            flags,
        )
        self._case_sensitive = case_sensitive
        self._ids = {
            item.value if case_sensitive else _ascii_lower(item.value): item.pattern_id
            for item in selected
        }

    def find(
        self,
        text: str,
        *,
        word_boundary: bool = False,
    ) -> tuple[LiteralSpan, ...]:
        expression = self._word if word_boundary else self._substring
        matches: list[LiteralSpan] = []
        for match in expression.finditer(text):
            value = match.group(0)
            comparable = value if self._case_sensitive else _ascii_lower(value)
            matches.append(
                LiteralSpan(match.start(), match.end(), self._ids[comparable])
            )
        return tuple(matches)


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


class TrieRegexMatcher(RegexAlternationMatcher):
    @staticmethod
    def _expression(patterns: tuple[LiteralPattern, ...]) -> str:
        root = _RegexTrieNode()
        for pattern in patterns:
            node = root
            for character in pattern.value:
                node = node.children.setdefault(character, _RegexTrieNode())
            node.terminal = True
        return _emit_regex_trie(root)


class AhoCorasickMatcher:
    def __init__(
        self,
        patterns: tuple[LiteralPattern, ...],
        *,
        case_sensitive: bool,
    ) -> None:
        selected = _validate_patterns(patterns, case_sensitive=case_sensitive)
        self._case_sensitive = case_sensitive
        self._transitions: list[dict[str, int]] = [{}]
        self._failures: list[int] = [0]
        self._outputs: list[list[tuple[str, int]]] = [[]]
        for item in selected:
            value = item.value if case_sensitive else _ascii_lower(item.value)
            state = 0
            for character in value:
                following = self._transitions[state].get(character)
                if following is None:
                    following = len(self._transitions)
                    self._transitions[state][character] = following
                    self._transitions.append({})
                    self._failures.append(0)
                    self._outputs.append([])
                state = following
            self._outputs[state].append((item.pattern_id, len(value)))

        pending: deque[int] = deque(self._transitions[0].values())
        while pending:
            state = pending.popleft()
            for character, following in self._transitions[state].items():
                pending.append(following)
                failure = self._failures[state]
                while failure and character not in self._transitions[failure]:
                    failure = self._failures[failure]
                self._failures[following] = self._transitions[failure].get(
                    character, 0
                )
                self._outputs[following].extend(
                    self._outputs[self._failures[following]]
                )

    def find(
        self,
        text: str,
        *,
        word_boundary: bool = False,
    ) -> tuple[LiteralSpan, ...]:
        state = 0
        matches: list[LiteralSpan] = []
        for position, original in enumerate(text):
            character = (
                original
                if self._case_sensitive or original not in string.ascii_uppercase
                else chr(ord(original) + 32)
            )
            while state and character not in self._transitions[state]:
                state = self._failures[state]
            state = self._transitions[state].get(character, 0)
            for pattern_id, length in self._outputs[state]:
                start = position - length + 1
                end = position + 1
                if not word_boundary or _has_ascii_word_boundaries(text, start, end):
                    matches.append(LiteralSpan(start, end, pattern_id))
        return _resolve(matches)


class ProductionTrieRegexMatcher:
    """Adapter that validates the shipped matcher against the same workloads."""

    def __init__(
        self,
        patterns: tuple[LiteralPattern, ...],
        *,
        case_sensitive: bool,
    ) -> None:
        selected = _validate_patterns(patterns, case_sensitive=case_sensitive)
        self._matcher = RuntimeLiteralMatcher(
            tuple(
                RuntimeLiteralDefinition(
                    item.pattern_id,
                    item.value,
                    case_sensitive=case_sensitive,
                )
                for item in selected
            )
        )

    def find(
        self,
        text: str,
        *,
        word_boundary: bool = False,
    ) -> tuple[LiteralSpan, ...]:
        if word_boundary:
            raise ValueError("production benchmark adapter expects substring mode")
        result = self._matcher.find(text, max_matches=4_096)
        if result.overflow:
            raise RuntimeError("benchmark workload exceeded its match budget")
        return tuple(
            LiteralSpan(item.start, item.end, item.pattern_id)
            for item in result.matches
        )


_MATCHERS = {
    "sequential": SequentialFindMatcher,
    "regex_flat": RegexAlternationMatcher,
    "regex_trie": TrieRegexMatcher,
    "aho": AhoCorasickMatcher,
    "runtime_trie": ProductionTrieRegexMatcher,
}


def _base36(value: int) -> str:
    alphabet = string.digits + string.ascii_lowercase
    result = ""
    while value:
        value, remainder = divmod(value, 36)
        result = alphabet[remainder] + result
    return (result or "0").rjust(4, "0")


def build_patterns(count: int) -> tuple[LiteralPattern, ...]:
    if not 3 <= count <= 1_024:
        raise ValueError("count must be between 3 and 1024")
    patterns = [
        LiteralPattern("literal.0000", "qzalpha"),
        LiteralPattern("literal.0001", "qzalphabet"),
        LiteralPattern("literal.0002", "qzalphabetic"),
    ]
    for index in range(3, count):
        suffix = chr(ord("a") + (index % 26)) * (3 + (index % 17))
        patterns.append(
            LiteralPattern(
                f"literal.{index:04d}",
                f"qzsharedprefix_{_base36(index)}_{suffix}",
            )
        )
    return tuple(patterns)


def _embed(size: int, values: tuple[str, ...]) -> str:
    positions = (101, size // 2, size - len(values[-1]) - 101)
    parts: list[str] = []
    cursor = 0
    for position, value in zip(positions, values, strict=True):
        if position < cursor or position + len(value) > size:
            raise ValueError("size is too small for deterministic markers")
        parts.append("x" * (position - cursor))
        parts.append(value)
        cursor = position + len(value)
    parts.append("x" * (size - cursor))
    return "".join(parts)


def _repeat_to_size(value: str, size: int) -> str:
    repetitions, remainder = divmod(size, len(value))
    return value * repetitions + value[:remainder]


def build_workloads(
    size: int,
    patterns: tuple[LiteralPattern, ...],
) -> dict[str, tuple[str, bool, bool]]:
    if size < 1_000:
        raise ValueError("size must be at least 1000")
    sparse = (patterns[3].value, patterns[len(patterns) // 2].value, patterns[-1].value)
    mixed = tuple(value.swapcase() for value in sparse)
    overlap = (patterns[2].value, patterns[2].value, patterns[2].value)
    return {
        "clean": ("x" * size, True, False),
        "prefix_dense": (
            _repeat_to_size("qzsharedprefix_zzzz_", size),
            True,
            False,
        ),
        "sparse_matches": (_embed(size, sparse), True, False),
        "overlap": (_embed(size, overlap), True, False),
        "case_mixed": (_embed(size, mixed), False, False),
    }


def _measure(callback: object, rounds: int) -> tuple[float, tuple[LiteralSpan, ...]]:
    if not callable(callback):
        raise TypeError("callback must be callable")
    durations: list[float] = []
    result: tuple[LiteralSpan, ...] = ()
    for _ in range(rounds):
        started = time.perf_counter()
        result = callback()
        durations.append(time.perf_counter() - started)
    return median(durations), result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=8_000_000)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--catalog-size", type=int, default=1_024)
    parser.add_argument("--min-throughput-mib-s", type=float, default=10.0)
    parser.add_argument("--max-build-ms", type=float, default=250.0)
    parser.add_argument("--max-build-peak-mib", type=float, default=32.0)
    parser.add_argument("--max-request-peak-mib", type=float, default=64.0)
    parser.add_argument(
        "--candidate",
        action="append",
        choices=tuple(_MATCHERS),
        help="measure only the named candidate; repeat to select multiple",
    )
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args()
    if args.size <= 0 or args.rounds <= 0:
        parser.error("--size and --rounds must be positive")

    patterns = build_patterns(args.catalog_size)
    workloads = build_workloads(args.size, patterns)
    mib = args.size / (1024 * 1024)
    references = {
        workload: SequentialFindMatcher(
            patterns, case_sensitive=case_sensitive
        ).find(text, word_boundary=word_boundary)
        for workload, (text, case_sensitive, word_boundary) in workloads.items()
    }
    qualified: list[str] = []
    selected_matchers = (
        tuple(args.candidate) if args.candidate else tuple(_MATCHERS)
    )
    for name in selected_matchers:
        matcher_type = _MATCHERS[name]
        re.purge()
        started = time.perf_counter()
        sensitive = matcher_type(patterns, case_sensitive=True)
        insensitive = matcher_type(patterns, case_sensitive=False)
        build_seconds = time.perf_counter() - started
        re.purge()
        tracemalloc.start()
        matcher_type(patterns, case_sensitive=True)
        matcher_type(patterns, case_sensitive=False)
        _, build_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        timings: dict[str, float] = {}
        valid = True
        for workload, (text, case_sensitive, word_boundary) in workloads.items():
            matcher = sensitive if case_sensitive else insensitive
            seconds, spans = _measure(
                lambda matcher=matcher, text=text, word_boundary=word_boundary: matcher.find(
                    text, word_boundary=word_boundary
                ),
                args.rounds,
            )
            if spans != references[workload]:
                valid = False
            timings[workload] = mib / seconds if seconds else float("inf")

        tracemalloc.start()
        sensitive.find(workloads["sparse_matches"][0])
        _, request_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        passes = (
            valid
            and timings["clean"] >= args.min_throughput_mib_s
            and timings["prefix_dense"] >= args.min_throughput_mib_s
            and build_seconds * 1_000 <= args.max_build_ms
            and build_peak / (1024 * 1024) <= args.max_build_peak_mib
            and request_peak / (1024 * 1024) <= args.max_request_peak_mib
        )
        if passes:
            qualified.append(name)
        print(
            f"matcher={name} valid={str(valid).lower()} qualified={str(passes).lower()} "
            f"build_ms={build_seconds * 1000:.3f} "
            f"build_peak_mib={build_peak / (1024 * 1024):.3f} "
            f"request_peak_mib={request_peak / (1024 * 1024):.3f}"
        )
        for workload, throughput in timings.items():
            print(
                f"matcher={name} workload={workload} throughput_mib_s={throughput:.3f}"
            )
    print(f"qualified_count={len(qualified)}")
    if args.require_qualified and not qualified:
        raise SystemExit("no literal matcher candidate met the selection gates")


if __name__ == "__main__":
    main()
