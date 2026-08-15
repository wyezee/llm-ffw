"""Configuration for the scanner engine."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScannerConfig:
    """Resource and redaction limits with conservative defaults."""

    max_input_chars: int = 1_000_000
    redaction_text: str = "[REDACTED]"

    def __post_init__(self) -> None:
        if isinstance(self.max_input_chars, bool) or not isinstance(
            self.max_input_chars, int
        ):
            raise TypeError("max_input_chars must be an integer")
        if self.max_input_chars <= 0:
            raise ValueError("max_input_chars must be positive")
        if not isinstance(self.redaction_text, str):
            raise TypeError("redaction_text must be a string")
        if not self.redaction_text:
            raise ValueError("redaction_text must not be empty")
