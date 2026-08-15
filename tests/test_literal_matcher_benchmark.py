import unittest

from benchmarks.bench_literal_matchers import (
    AhoCorasickMatcher,
    LiteralPattern,
    LiteralSpan,
    RegexAlternationMatcher,
    SequentialFindMatcher,
    TrieRegexMatcher,
)


_MATCHERS = (
    SequentialFindMatcher,
    RegexAlternationMatcher,
    TrieRegexMatcher,
    AhoCorasickMatcher,
)
_PATTERNS = (
    LiteralPattern("short", "alpha"),
    LiteralPattern("long", "alphabet"),
    LiteralPattern("other", "bravo"),
)


class LiteralMatcherBenchmarkTests(unittest.TestCase):
    def test_candidates_select_identical_leftmost_longest_spans(self) -> None:
        expected = (
            LiteralSpan(2, 10, "long"),
            LiteralSpan(11, 16, "other"),
        )
        for matcher_type in _MATCHERS:
            with self.subTest(matcher=matcher_type.__name__):
                matcher = matcher_type(_PATTERNS, case_sensitive=True)
                self.assertEqual(matcher.find("--alphabet bravo--"), expected)

    def test_candidates_use_ascii_only_case_insensitivity(self) -> None:
        expected = (LiteralSpan(0, 8, "long"),)
        for matcher_type in _MATCHERS:
            with self.subTest(matcher=matcher_type.__name__):
                matcher = matcher_type(_PATTERNS, case_sensitive=False)
                self.assertEqual(matcher.find("ALPHABET"), expected)
                self.assertEqual(matcher.find("İALPHABET"), (LiteralSpan(1, 9, "long"),))

    def test_candidates_apply_explicit_ascii_word_boundaries(self) -> None:
        patterns = (LiteralPattern("word", "alpha"),)
        expected = (LiteralSpan(7, 12, "word"),)
        text = "xalpha alpha-é"
        for matcher_type in _MATCHERS:
            with self.subTest(matcher=matcher_type.__name__):
                matcher = matcher_type(patterns, case_sensitive=True)
                self.assertEqual(
                    matcher.find(text, word_boundary=True),
                    expected,
                )

    def test_catalog_validation_rejects_case_collisions(self) -> None:
        patterns = (
            LiteralPattern("one", "Alpha"),
            LiteralPattern("two", "alpha"),
        )
        for matcher_type in _MATCHERS:
            with self.subTest(matcher=matcher_type.__name__):
                with self.assertRaisesRegex(ValueError, "unique"):
                    matcher_type(patterns, case_sensitive=False)


if __name__ == "__main__":
    unittest.main()
