"""Bounded configuration for HTTP Authorization-header inspection."""

from dataclasses import dataclass

from .inspection import ScanScope


_HARD_MAX_CANDIDATES = 1_024
_HARD_MAX_CREDENTIAL_CHARS = 65_536


@dataclass(frozen=True, slots=True)
class AuthorizationHeaderConfig:
    """Directions and resource limits for Basic and Bearer credentials."""

    max_candidates: int = 128
    max_credential_chars: int = 8_192
    scopes: tuple[ScanScope, ...] = (ScanScope.INPUT, ScanScope.OUTPUT)

    def __post_init__(self) -> None:
        limits = (
            ("max_candidates", self.max_candidates, _HARD_MAX_CANDIDATES),
            (
                "max_credential_chars",
                self.max_credential_chars,
                _HARD_MAX_CREDENTIAL_CHARS,
            ),
        )
        for name, value, hard_maximum in limits:
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
            if value <= 0 or value > hard_maximum:
                raise ValueError(f"{name} must be between 1 and {hard_maximum}")
        if isinstance(self.scopes, (str, bytes)):
            raise TypeError("scopes must be an iterable of ScanScope values")
        try:
            scopes = tuple(self.scopes)
        except TypeError as exc:
            raise TypeError(
                "scopes must be an iterable of ScanScope values"
            ) from exc
        text_scopes = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))
        if not scopes or any(
            not isinstance(scope, ScanScope) or scope not in text_scopes
            for scope in scopes
        ):
            raise ValueError("scopes must contain input or output ScanScope values")
        object.__setattr__(
            self,
            "scopes",
            tuple(sorted(set(scopes), key=lambda scope: scope.value)),
        )


__all__ = ["AuthorizationHeaderConfig"]
