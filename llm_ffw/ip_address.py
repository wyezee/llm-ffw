"""Bounded configuration for deterministic IP-address inspection."""

from dataclasses import dataclass

from .inspection import ScanScope


_HARD_MAX_CANDIDATES = 1_024


@dataclass(frozen=True, slots=True)
class IPAddressConfig:
    """Address families, directions, and resource limits to inspect."""

    max_candidates: int = 128
    include_ipv4: bool = True
    include_ipv6: bool = True
    scopes: tuple[ScanScope, ...] = (ScanScope.INPUT,)

    def __post_init__(self) -> None:
        if isinstance(self.max_candidates, bool) or not isinstance(
            self.max_candidates,
            int,
        ):
            raise TypeError("max_candidates must be an integer")
        if self.max_candidates <= 0:
            raise ValueError("max_candidates must be positive")
        if self.max_candidates > _HARD_MAX_CANDIDATES:
            raise ValueError(
                f"max_candidates must not exceed {_HARD_MAX_CANDIDATES}"
            )
        for field_name in ("include_ipv4", "include_ipv6"):
            if not isinstance(getattr(self, field_name), bool):
                raise TypeError(f"{field_name} must be a boolean")
        if not self.include_ipv4 and not self.include_ipv6:
            raise ValueError("at least one address family must be enabled")
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


__all__ = ["IPAddressConfig"]
