"""Bounded configuration for deterministic unsafe-URL inspection."""

from dataclasses import dataclass

from .inspection import ScanScope


_HARD_MAX_CANDIDATES = 1_024
_HARD_MAX_URL_CHARS = 65_536


@dataclass(frozen=True, slots=True)
class UnsafeURLConfig:
    """Directions and resource limits for URL candidates."""

    max_candidates: int = 128
    max_url_chars: int = 2_048
    scopes: tuple[ScanScope, ...] = (ScanScope.INPUT, ScanScope.OUTPUT)

    def __post_init__(self) -> None:
        for field_name in ("max_candidates", "max_url_chars"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{field_name} must be an integer")
            if value <= 0:
                raise ValueError(f"{field_name} must be positive")
        if self.max_candidates > _HARD_MAX_CANDIDATES:
            raise ValueError(
                f"max_candidates must not exceed {_HARD_MAX_CANDIDATES}"
            )
        if self.max_url_chars > _HARD_MAX_URL_CHARS:
            raise ValueError(
                f"max_url_chars must not exceed {_HARD_MAX_URL_CHARS}"
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


__all__ = ["UnsafeURLConfig"]
