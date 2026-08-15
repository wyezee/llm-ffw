"""Bounded configuration for strict JSON output validation."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class JSONOutputConfig:
    """Resource limits and interoperability checks for one JSON document."""

    max_document_chars: int = 8_000_000
    max_depth: int = 64
    max_structure_tokens: int = 100_000
    max_number_chars: int = 128
    reject_duplicate_keys: bool = True

    def __post_init__(self) -> None:
        for field_name in (
            "max_document_chars",
            "max_depth",
            "max_structure_tokens",
            "max_number_chars",
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an integer")
            if value <= 0:
                raise ValueError(f"{field_name} must be positive")
        if not isinstance(self.reject_duplicate_keys, bool):
            raise TypeError("reject_duplicate_keys must be a boolean")


__all__ = ["JSONOutputConfig"]
