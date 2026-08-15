"""Length-aware normalization with exact original-offset mapping."""

from dataclasses import dataclass

from .findings import Span


@dataclass(frozen=True, slots=True)
class NormalizedText:
    """Normalized text and a map from its boundaries to original offsets."""

    original: str
    text: str
    _original_boundaries: tuple[int, ...] | None

    def original_span(self, start: int, end: int) -> Span:
        """Translate a valid normalized half-open span to original offsets."""

        if not 0 <= start <= end <= len(self.text):
            raise ValueError("normalized span is outside the text")
        if self._original_boundaries is None:
            return Span(start, end)
        return Span(
            self._original_boundaries[start],
            self._original_boundaries[end],
        )


def normalize_text(text: str) -> NormalizedText:
    """Normalize CRLF and CR line endings to LF while preserving span mapping."""

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if "\r" not in text:
        return NormalizedText(text, text, None)

    characters: list[str] = []
    boundaries = [0]
    index = 0
    while index < len(text):
        if text[index] == "\r":
            index += 1
            if index < len(text) and text[index] == "\n":
                index += 1
            characters.append("\n")
        else:
            characters.append(text[index])
            index += 1
        boundaries.append(index)

    return NormalizedText(text, "".join(characters), tuple(boundaries))
