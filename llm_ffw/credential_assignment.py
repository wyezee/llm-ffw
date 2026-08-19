"""Bounded configuration for credential-assignment inspection."""

from dataclasses import dataclass, field
import re

from .inspection import ScanScope


_HARD_MAX_CANDIDATES = 1_024
_HARD_MAX_VALUE_CHARS = 65_536
_HARD_MAX_ADDITIONAL_KEYWORDS = 256
_KEYWORD = re.compile(r"[a-z][a-z0-9_.-]{1,127}\Z", re.ASCII)

BUILTIN_CREDENTIAL_ASSIGNMENT_KEYWORDS = (
    "access_token",
    "api_key",
    "api_secret",
    "apikey",
    "auth_token",
    "aws_secret_access_key",
    "client_secret",
    "passwd",
    "password",
    "private_token",
    "pwd",
    "refresh_token",
)


def _normalized_keyword(value: str) -> str:
    return value.replace("-", "_").replace(".", "_")


def _matches_builtin_keyword(value: str) -> bool:
    return any(
        value == keyword or value.endswith("_" + keyword)
        for keyword in BUILTIN_CREDENTIAL_ASSIGNMENT_KEYWORDS
    )


@dataclass(frozen=True, slots=True)
class CredentialAssignmentConfig:
    """Directions, exact extensions, and limits for assigned credentials."""

    max_candidates: int = 128
    max_value_chars: int = 8_192
    additional_keywords: tuple[str, ...] = field(default=(), repr=False)
    scopes: tuple[ScanScope, ...] = (ScanScope.INPUT, ScanScope.OUTPUT)

    def __post_init__(self) -> None:
        limits = (
            ("max_candidates", self.max_candidates, _HARD_MAX_CANDIDATES),
            ("max_value_chars", self.max_value_chars, _HARD_MAX_VALUE_CHARS),
        )
        for name, value, hard_maximum in limits:
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
            if value <= 0 or value > hard_maximum:
                raise ValueError(f"{name} must be between 1 and {hard_maximum}")

        if isinstance(self.additional_keywords, (str, bytes)):
            raise TypeError("additional_keywords must be an iterable of strings")
        try:
            additional_keywords = tuple(self.additional_keywords)
        except TypeError as exc:
            raise TypeError(
                "additional_keywords must be an iterable of strings"
            ) from exc
        if len(additional_keywords) > _HARD_MAX_ADDITIONAL_KEYWORDS:
            raise ValueError(
                "additional_keywords must contain at most "
                f"{_HARD_MAX_ADDITIONAL_KEYWORDS} values"
            )
        if any(
            not isinstance(value, str) or _KEYWORD.fullmatch(value) is None
            for value in additional_keywords
        ):
            raise ValueError(
                "additional_keywords must contain lowercase ASCII field names"
            )
        normalized_keywords = {
            _normalized_keyword(value) for value in additional_keywords
        }
        object.__setattr__(
            self,
            "additional_keywords",
            tuple(
                sorted(
                    value
                    for value in normalized_keywords
                    if not _matches_builtin_keyword(value)
                )
            ),
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
    "BUILTIN_CREDENTIAL_ASSIGNMENT_KEYWORDS",
    "CredentialAssignmentConfig",
]
