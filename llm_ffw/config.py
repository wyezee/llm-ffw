"""Configuration for the scanner engine."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RuleScannerConfig:
    """Resource and redaction limits with conservative defaults."""

    max_input_chars: int = 8_000_000
    redaction_text: str = "[REDACTED]"
    enable_invisible_characters: bool = True
    enable_unicode_tag_smuggling: bool = True
    enable_payment_cards: bool = True
    enable_private_keys: bool = True
    enable_jwt_tokens: bool = True

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
        if not isinstance(self.enable_invisible_characters, bool):
            raise TypeError("enable_invisible_characters must be a boolean")
        if not isinstance(self.enable_unicode_tag_smuggling, bool):
            raise TypeError("enable_unicode_tag_smuggling must be a boolean")
        if not isinstance(self.enable_payment_cards, bool):
            raise TypeError("enable_payment_cards must be a boolean")
        if not isinstance(self.enable_private_keys, bool):
            raise TypeError("enable_private_keys must be a boolean")
        if not isinstance(self.enable_jwt_tokens, bool):
            raise TypeError("enable_jwt_tokens must be a boolean")


# Compatibility alias retained through the pre-1.0 migration window.
ScannerConfig = RuleScannerConfig


__all__ = ["RuleScannerConfig", "ScannerConfig"]
