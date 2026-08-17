"""Bounded configuration and pinned registry data for IBAN inspection."""

from dataclasses import dataclass
from types import MappingProxyType

from .inspection import ScanScope


IBAN_REGISTRY_RELEASE = "102"
IBAN_REGISTRY_ISSUED = "2026-06"

# ISO 13616-compliant national lengths from the SWIFT IBAN Registry,
# Release 102 (June 2026). That release changed contact information only.
IBAN_LENGTHS = MappingProxyType(
    {
        "AD": 24,
        "AE": 23,
        "AL": 28,
        "AT": 20,
        "AZ": 28,
        "BA": 20,
        "BE": 16,
        "BG": 22,
        "BH": 22,
        "BI": 27,
        "BR": 29,
        "BY": 28,
        "CH": 21,
        "CR": 22,
        "CY": 28,
        "CZ": 24,
        "DE": 22,
        "DJ": 27,
        "DK": 18,
        "DO": 28,
        "EE": 20,
        "EG": 29,
        "ES": 24,
        "FI": 18,
        "FK": 18,
        "FO": 18,
        "FR": 27,
        "GB": 22,
        "GE": 22,
        "GI": 23,
        "GL": 18,
        "GR": 27,
        "GT": 28,
        "HN": 28,
        "HR": 21,
        "HU": 28,
        "IE": 22,
        "IL": 23,
        "IQ": 23,
        "IS": 26,
        "IT": 27,
        "JO": 30,
        "KW": 30,
        "KZ": 20,
        "LB": 28,
        "LC": 32,
        "LI": 21,
        "LT": 20,
        "LU": 20,
        "LV": 21,
        "LY": 25,
        "MC": 27,
        "MD": 24,
        "ME": 22,
        "MK": 19,
        "MN": 20,
        "MR": 27,
        "MT": 31,
        "MU": 30,
        "NI": 28,
        "NL": 18,
        "NO": 15,
        "OM": 23,
        "PK": 24,
        "PL": 28,
        "PS": 29,
        "PT": 25,
        "QA": 29,
        "RO": 24,
        "RS": 22,
        "RU": 33,
        "SA": 24,
        "SC": 31,
        "SD": 18,
        "SE": 24,
        "SI": 19,
        "SK": 24,
        "SM": 27,
        "SO": 23,
        "ST": 25,
        "SV": 28,
        "TL": 23,
        "TN": 24,
        "TR": 26,
        "UA": 29,
        "VA": 22,
        "VG": 24,
        "XK": 20,
        "YE": 30,
    }
)

_HARD_MAX_CANDIDATES = 1_024


@dataclass(frozen=True, slots=True)
class IBANConfig:
    """Directions and resource limits for registered IBAN inspection."""

    max_candidates: int = 128
    scopes: tuple[ScanScope, ...] = (ScanScope.INPUT,)

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


__all__ = [
    "IBANConfig",
    "IBAN_LENGTHS",
    "IBAN_REGISTRY_ISSUED",
    "IBAN_REGISTRY_RELEASE",
]
