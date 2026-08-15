"""Bounded configuration for deterministic payment-card inspection."""

from dataclasses import dataclass

from .inspection import ScanScope


_HARD_MAX_CANDIDATES = 1_024


@dataclass(frozen=True, slots=True)
class PaymentCardConfig:
    """Directions and resource limits for payment-card candidates."""

    max_candidates: int = 128
    scopes: tuple[ScanScope, ...] = (ScanScope.INPUT, ScanScope.OUTPUT)

    def __post_init__(self) -> None:
        if isinstance(self.max_candidates, bool) or not isinstance(
            self.max_candidates, int
        ):
            raise TypeError("max_candidates must be an integer")
        if self.max_candidates <= 0:
            raise ValueError("max_candidates must be positive")
        if self.max_candidates > _HARD_MAX_CANDIDATES:
            raise ValueError(
                f"max_candidates must not exceed {_HARD_MAX_CANDIDATES}"
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


__all__ = ["PaymentCardConfig"]
