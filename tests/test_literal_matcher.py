import unittest

from llm_ffw.literal_matcher import (
    LiteralDefinition,
    LiteralMatch,
    LiteralMatcher,
    LiteralMatchMode,
)


class LiteralMatcherTests(unittest.TestCase):
    def test_mixed_groups_return_leftmost_longest_stable_spans(self) -> None:
        matcher = LiteralMatcher(
            (
                LiteralDefinition("short", "alpha", case_sensitive=True),
                LiteralDefinition("long", "alphabet", case_sensitive=True),
                LiteralDefinition(
                    "word",
                    "bravo",
                    match_mode=LiteralMatchMode.ASCII_WORD,
                ),
                LiteralDefinition("case", "charlie"),
            )
        )

        result = matcher.find(
            "--alphabet xbravo bravo CHARLIE--",
            max_matches=64,
        )

        self.assertFalse(result.overflow)
        self.assertEqual(
            result.matches,
            (
                LiteralMatch(2, 10, "long"),
                LiteralMatch(18, 23, "word"),
                LiteralMatch(24, 31, "case"),
            ),
        )

    def test_ascii_case_and_word_boundaries_do_not_fold_unicode(self) -> None:
        matcher = LiteralMatcher(
            (
                LiteralDefinition(
                    "word",
                    "alpha",
                    match_mode=LiteralMatchMode.ASCII_WORD,
                ),
            )
        )

        result = matcher.find("İALPHAé", max_matches=2)

        self.assertEqual(result.matches, (LiteralMatch(1, 6, "word"),))

    def test_overflow_is_bounded_without_retaining_matched_text(self) -> None:
        matcher = LiteralMatcher((LiteralDefinition("token", "abc"),))

        result = matcher.find("abc " * 10_000, max_matches=64)

        self.assertTrue(result.overflow)
        self.assertEqual(len(result.matches), 64)
        self.assertNotIn("abc", repr(result.matches))

    def test_rejects_unsafe_or_ambiguous_catalogs(self) -> None:
        with self.assertRaisesRegex(ValueError, "printable ASCII"):
            LiteralDefinition("bad", "ab\n")
        with self.assertRaisesRegex(ValueError, "unique ignoring ASCII case"):
            LiteralMatcher(
                (
                    LiteralDefinition("one", "Alpha"),
                    LiteralDefinition("two", "alpha"),
                )
            )
        with self.assertRaisesRegex(ValueError, "unique"):
            LiteralMatcher(
                (
                    LiteralDefinition("same", "alpha"),
                    LiteralDefinition("same", "bravo"),
                )
            )

    def test_long_shared_prefix_non_match_is_fast_and_empty(self) -> None:
        definitions = tuple(
            LiteralDefinition(
                f"pattern.{index}",
                f"shared-prefix-{index:04d}",
                case_sensitive=True,
            )
            for index in range(1_000)
        )
        matcher = LiteralMatcher(definitions)

        result = matcher.find("shared-prefix-zzzz" * 50_000, max_matches=64)

        self.assertEqual(result.matches, ())
        self.assertFalse(result.overflow)


if __name__ == "__main__":
    unittest.main()
