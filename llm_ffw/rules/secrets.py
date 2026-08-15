"""Detection of explicitly formatted, well-known credential types."""

from dataclasses import dataclass
import re
from typing import Pattern

from ..findings import Action, Severity, Span
from .base import Rule, RuleMatch


@dataclass(frozen=True, slots=True)
class _Signature:
    secret_type: str
    pattern: Pattern[str]


class SecretsRule(Rule):
    """Find credentials with stable prefixes and redact them as high severity."""

    _RULE_ID = "secrets.detected"
    _PURPOSE = "Detect explicitly formatted credentials with well-known prefixes."
    _SIGNATURES = (
        _Signature(
            "openai_api_key",
            re.compile(
                r"(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-)?"
                r"[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])",
                re.ASCII,
            ),
        ),
        _Signature(
            "github_token",
            re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b", re.ASCII),
        ),
        _Signature(
            "aws_access_key_id",
            re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", re.ASCII),
        ),
    )

    @property
    def rule_id(self) -> str:
        return self._RULE_ID

    @property
    def purpose(self) -> str:
        return self._PURPOSE

    def scan(self, text: str) -> tuple[RuleMatch, ...]:
        if not isinstance(text, str):
            raise TypeError("text must be a string")

        matches: list[RuleMatch] = []
        for signature in self._SIGNATURES:
            for match in signature.pattern.finditer(text):
                matches.append(
                    RuleMatch(
                        span=Span(match.start(), match.end()),
                        severity=Severity.HIGH,
                        action=Action.REDACT,
                        message=f"Potential {signature.secret_type} credential detected.",
                        redacted_preview=f"[REDACTED:{signature.secret_type}]",
                        metadata={
                            "secret_type": signature.secret_type,
                            "detector": "well_known_prefix",
                            "span_basis": "characters",
                        },
                    )
                )
        return tuple(
            sorted(
                matches,
                key=lambda item: (
                    item.span.start,
                    item.span.end,
                    item.metadata["secret_type"],
                ),
            )
        )
