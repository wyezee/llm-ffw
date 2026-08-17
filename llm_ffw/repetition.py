"""Bounded configuration for deterministic excessive-repetition inspection."""

from dataclasses import dataclass

from .inspection import ScanScope


_HARD_MAX_FINDINGS = 1_024
_HARD_MAX_THRESHOLD = 4_096


@dataclass(frozen=True, slots=True)
class RepetitionConfig:
    """Conservative repetition thresholds, directions, and resource limits."""

    character_run_threshold: int = 256
    token_repeat_threshold: int = 64
    line_repeat_threshold: int = 32
    max_findings: int = 64
    scopes: tuple[ScanScope, ...] = (ScanScope.INPUT, ScanScope.OUTPUT)

    def __post_init__(self) -> None:
        limits = (
            ("character_run_threshold", self.character_run_threshold, 8),
            ("token_repeat_threshold", self.token_repeat_threshold, 4),
            ("line_repeat_threshold", self.line_repeat_threshold, 3),
            ("max_findings", self.max_findings, 1),
        )
        for field_name, value, minimum in limits:
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an integer")
            if value < minimum:
                raise ValueError(f"{field_name} must be at least {minimum}")
            if field_name.endswith("threshold") and value > _HARD_MAX_THRESHOLD:
                raise ValueError(
                    f"{field_name} must not exceed {_HARD_MAX_THRESHOLD}"
                )
        if self.max_findings > _HARD_MAX_FINDINGS:
            raise ValueError(
                f"max_findings must not exceed {_HARD_MAX_FINDINGS}"
            )
        if isinstance(self.scopes, (str, bytes)):
            raise TypeError("scopes must be an iterable of ScanScope values")
        try:
            scopes = tuple(self.scopes)
        except TypeError as exc:
            raise TypeError(
                "scopes must be an iterable of ScanScope values"
            ) from exc
        if not scopes or any(not isinstance(scope, ScanScope) for scope in scopes):
            raise ValueError("scopes must contain ScanScope values")
        object.__setattr__(
            self,
            "scopes",
            tuple(sorted(set(scopes), key=lambda scope: scope.value)),
        )


__all__ = ["RepetitionConfig"]
