"""Scanner orchestration and safe redaction."""

from collections.abc import Iterable

from .config import ScannerConfig
from .findings import Action, Finding, Span
from .normalizers import normalize_text
from .rules.base import Rule, RuleMatch
from .rules.secrets import SecretsRule


class Scanner:
    """Run deterministic rules and return findings in a stable order."""

    def __init__(
        self,
        rules: Iterable[Rule] | None = None,
        config: ScannerConfig | None = None,
    ) -> None:
        self._config = config if config is not None else ScannerConfig()
        if not isinstance(self._config, ScannerConfig):
            raise TypeError("config must be a ScannerConfig")

        selected_rules = (SecretsRule(),) if rules is None else tuple(rules)
        rule_ids: set[str] = set()
        for rule in selected_rules:
            if not isinstance(rule, Rule):
                raise TypeError("rules must contain Rule instances")
            if not rule.rule_id:
                raise ValueError("rule_id must not be empty")
            if rule.rule_id in rule_ids:
                raise ValueError(f"duplicate rule_id: {rule.rule_id}")
            rule_ids.add(rule.rule_id)
        self._rules = tuple(sorted(selected_rules, key=lambda rule: rule.rule_id))

    @property
    def config(self) -> ScannerConfig:
        return self._config

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def scan(self, text: str) -> tuple[Finding, ...]:
        """Scan text and return immutable findings using original-text spans."""

        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if len(text) > self._config.max_input_chars:
            raise ValueError("text exceeds max_input_chars")

        normalized = normalize_text(text)
        findings: list[Finding] = []
        for rule in self._rules:
            for match in rule.scan(normalized.text):
                if not isinstance(match, RuleMatch):
                    raise TypeError(
                        f"rule {rule.rule_id} returned a non-RuleMatch value"
                    )
                original_span = normalized.original_span(
                    match.span.start, match.span.end
                )
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        severity=match.severity,
                        action=match.action,
                        span=original_span,
                        message=match.message,
                        redacted_preview=match.redacted_preview,
                        metadata=match.metadata,
                    )
                )

        return tuple(
            sorted(
                findings,
                key=lambda finding: (
                    finding.span.start,
                    finding.span.end,
                    finding.rule_id,
                    tuple(sorted(finding.metadata.items())),
                ),
            )
        )

    def redact(
        self,
        text: str,
        findings: Iterable[Finding] | None = None,
    ) -> str:
        """Replace finding spans without reading or exposing their contents."""

        if not isinstance(text, str):
            raise TypeError("text must be a string")
        selected = self.scan(text) if findings is None else tuple(findings)
        if not selected:
            return text

        spans: list[Span] = []
        for finding in selected:
            if not isinstance(finding, Finding):
                raise TypeError("findings must contain Finding instances")
            if finding.span.end > len(text):
                raise ValueError("finding span is outside text")
            if finding.action is Action.REDACT:
                spans.append(finding.span)

        if not spans:
            return text

        merged: list[Span] = []
        for span in sorted(spans):
            if merged and span.start <= merged[-1].end:
                previous = merged[-1]
                merged[-1] = Span(previous.start, max(previous.end, span.end))
            else:
                merged.append(span)

        redacted = text
        for span in reversed(merged):
            redacted = (
                redacted[: span.start]
                + self._config.redaction_text
                + redacted[span.end :]
            )
        return redacted
