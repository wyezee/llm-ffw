"""Bounded configuration for deterministic private-key inspection."""

from dataclasses import dataclass

from .inspection import ScanScope


_HARD_MAX_CANDIDATES = 256
_HARD_MAX_BLOCK_CHARS = 8_000_000


@dataclass(frozen=True, slots=True)
class PrivateKeyConfig:
    """Directions and resource limits for armored private-key blocks."""

    max_candidates: int = 32
    max_block_chars: int = 262_144
    scopes: tuple[ScanScope, ...] = (ScanScope.INPUT, ScanScope.OUTPUT)

    def __post_init__(self) -> None:
        for field_name, hard_limit in (
            ("max_candidates", _HARD_MAX_CANDIDATES),
            ("max_block_chars", _HARD_MAX_BLOCK_CHARS),
        ):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an integer")
            if value <= 0:
                raise ValueError(f"{field_name} must be positive")
            if value > hard_limit:
                raise ValueError(f"{field_name} must not exceed {hard_limit}")
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


__all__ = ["PrivateKeyConfig"]
