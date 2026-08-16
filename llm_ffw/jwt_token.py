"""Bounded configuration for deterministic JWT inspection."""

from dataclasses import dataclass

from .inspection import ScanScope


_HARD_MAX_CANDIDATES = 1_024
_HARD_MAX_TOKEN_CHARS = 8_000_000
_HARD_MAX_JSON_DEPTH = 256
_HARD_MAX_JSON_STRUCTURE_TOKENS = 65_536


@dataclass(frozen=True, slots=True)
class JWTTokenConfig:
    """Directions and resource limits for compact JWT candidates."""

    max_candidates: int = 128
    max_token_chars: int = 131_072
    max_json_depth: int = 64
    max_json_structure_tokens: int = 4_096
    scopes: tuple[ScanScope, ...] = (ScanScope.INPUT, ScanScope.OUTPUT)

    def __post_init__(self) -> None:
        for field_name, hard_limit in (
            ("max_candidates", _HARD_MAX_CANDIDATES),
            ("max_token_chars", _HARD_MAX_TOKEN_CHARS),
            ("max_json_depth", _HARD_MAX_JSON_DEPTH),
            (
                "max_json_structure_tokens",
                _HARD_MAX_JSON_STRUCTURE_TOKENS,
            ),
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


__all__ = ["JWTTokenConfig"]
