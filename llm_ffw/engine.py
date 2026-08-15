"""Scanner orchestration and safe redaction."""

from collections.abc import Iterable

from .config import ScannerConfig
from .findings import Finding
from .inspection import InspectionFeature, ScanScope, build_inspection
from .redaction import sanitize_findings
from .rules.base import Rule, RuleMatch
from .rules.invisible_characters import InvisibleCharactersRule
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

        if rules is None:
            defaults: list[Rule] = [SecretsRule()]
            if self._config.enable_invisible_characters:
                defaults.append(InvisibleCharactersRule())
            selected_rules = tuple(defaults)
        else:
            selected_rules = tuple(rules)
        rule_ids: set[str] = set()
        rule_contracts: list[
            tuple[Rule, frozenset[ScanScope], frozenset[InspectionFeature]]
        ] = []
        for rule in selected_rules:
            if not isinstance(rule, Rule):
                raise TypeError("rules must contain Rule instances")
            if not rule.rule_id:
                raise ValueError("rule_id must not be empty")
            if rule.rule_id in rule_ids:
                raise ValueError(f"duplicate rule_id: {rule.rule_id}")
            rule_ids.add(rule.rule_id)
            try:
                scopes = frozenset(rule.scopes)
            except TypeError as exc:
                raise TypeError(f"rule {rule.rule_id} scopes must be iterable") from exc
            if not scopes or any(not isinstance(scope, ScanScope) for scope in scopes):
                raise ValueError(
                    f"rule {rule.rule_id} scopes must contain ScanScope values"
                )
            try:
                features = frozenset(rule.inspection_features)
            except TypeError as exc:
                raise TypeError(
                    f"rule {rule.rule_id} inspection_features must be iterable"
                ) from exc
            if any(not isinstance(item, InspectionFeature) for item in features):
                raise ValueError(
                    f"rule {rule.rule_id} inspection_features must contain "
                    "InspectionFeature values"
                )
            rule_contracts.append((rule, scopes, features))
        self._rule_contracts = tuple(
            sorted(rule_contracts, key=lambda item: item[0].rule_id)
        )
        self._rules = tuple(item[0] for item in self._rule_contracts)

    @property
    def config(self) -> ScannerConfig:
        return self._config

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def scan(
        self,
        text: str,
        *,
        scope: ScanScope = ScanScope.INPUT,
        prompt_context: str | None = None,
    ) -> tuple[Finding, ...]:
        """Scan text and return immutable findings using original-text spans."""

        self._validate_request(text, scope, prompt_context)

        active_contracts = tuple(
            contract for contract in self._rule_contracts if scope in contract[1]
        )
        if not active_contracts:
            return ()
        features = frozenset(
            feature
            for _, _, required_features in active_contracts
            for feature in required_features
        )
        inspection = build_inspection(
            text,
            scope=scope,
            features=features,
            prompt_context=prompt_context,
        )
        findings: list[Finding] = []
        for rule, _, _ in active_contracts:
            for match in rule.scan(inspection):
                if not isinstance(match, RuleMatch):
                    raise TypeError(
                        f"rule {rule.rule_id} returned a non-RuleMatch value"
                    )
                original_span = inspection.original_span(
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
        *,
        scope: ScanScope = ScanScope.INPUT,
        prompt_context: str | None = None,
    ) -> str:
        """Apply REMOVE and REDACT spans without exposing their contents."""

        self._validate_request(text, scope, prompt_context)
        selected = (
            self.scan(text, scope=scope, prompt_context=prompt_context)
            if findings is None
            else tuple(findings)
        )
        return sanitize_findings(text, selected, self._config.redaction_text)

    def _validate_request(
        self,
        text: object,
        scope: object,
        prompt_context: object,
    ) -> None:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if len(text) > self._config.max_input_chars:
            raise ValueError("text exceeds max_input_chars")
        if not isinstance(scope, ScanScope):
            raise TypeError("scope must be a ScanScope")
        if prompt_context is not None and not isinstance(prompt_context, str):
            raise TypeError("prompt_context must be a string or None")
        if scope is ScanScope.INPUT and prompt_context is not None:
            raise ValueError("prompt_context is only valid for output scans")
        if (
            isinstance(prompt_context, str)
            and len(prompt_context) > self._config.max_input_chars
        ):
            raise ValueError("prompt_context exceeds max_input_chars")
