import unittest

from llm_ffw.normalizers import normalize_text


class NormalizeTextTests(unittest.TestCase):
    def test_normalizes_line_endings(self) -> None:
        normalized = normalize_text("one\r\ntwo\rthree\nfour")

        self.assertEqual(normalized.text, "one\ntwo\nthree\nfour")

    def test_maps_normalized_span_to_original_text(self) -> None:
        original = "prefix\r\nvalue\rtrailer"
        normalized = normalize_text(original)
        start = normalized.text.index("value")
        span = normalized.original_span(start, start + len("value"))

        self.assertEqual(original[span.start : span.end], "value")
        self.assertEqual((span.start, span.end), (8, 13))

    def test_rejects_non_string_input(self) -> None:
        with self.assertRaises(TypeError):
            normalize_text(None)  # type: ignore[arg-type]
