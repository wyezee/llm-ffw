"""Immutable policy enforcement for deterministic scanner findings."""

from dataclasses import dataclass, field, replace
import re
from types import MappingProxyType
from typing import Mapping

from .engine import Scanner
from .findings import Action, Finding
from .inspection import ScanScope
from .redaction import redact_findings


_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?\Z")
_VERSION = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?\Z")
_ACTION_PRIORITY = {
    Action.ALLOW: 0,
    Action.REVIEW: 1,
    Action.REDACT: 2,
    Action.BLOCK: 3,
}


@dataclass(frozen=True, slots=True)
class PolicyOverride:
    """Override one rule's recommended action for one scan direction."""

    rule_id: str
    scope: ScanScope
    action: Action

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not _IDENTIFIER.fullmatch(
            self.rule_id
        ):
            raise ValueError("rule_id must be a stable lowercase identifier")
        if not isinstance(self.scope, ScanScope):
            raise TypeError("scope must be a ScanScope")
        if not isinstance(self.action, Action):
            raise TypeError("action must be an Action")


@dataclass(frozen=True, slots=True)
class FirewallResult:
    """Effective decision and text processed according to the selected policy."""

    policy_id: str
    policy_version: str
    scope: ScanScope
    decision: Action
    processed_text: str | None
    findings: tuple[Finding, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or not _IDENTIFIER.fullmatch(
            self.policy_id
        ):
            raise ValueError("policy_id must be a stable lowercase identifier")
        if not isinstance(self.policy_version, str) or not _VERSION.fullmatch(
            self.policy_version
        ):
            raise ValueError("policy_version must be a stable identifier")
        if not isinstance(self.scope, ScanScope):
            raise TypeError("scope must be a ScanScope")
        if not isinstance(self.decision, Action):
            raise TypeError("decision must be an Action")
        if self.processed_text is not None and not isinstance(
            self.processed_text, str
        ):
            raise TypeError("processed_text must be a string or None")
        try:
            findings = tuple(self.findings)
        except TypeError as exc:
            raise TypeError("findings must be iterable") from exc
        if any(not isinstance(item, Finding) for item in findings):
            raise TypeError("findings must contain Finding instances")
        expected_decision = max(
            (item.action for item in findings),
            key=_ACTION_PRIORITY.__getitem__,
            default=Action.ALLOW,
        )
        if self.decision is not expected_decision:
            raise ValueError("decision must equal the strongest finding action")
        if self.decision is Action.BLOCK and self.processed_text is not None:
            raise ValueError("blocked results must not contain processed_text")
        if self.decision is not Action.BLOCK and self.processed_text is None:
            raise ValueError("non-blocked results must contain processed_text")
        object.__setattr__(self, "findings", findings)

    @property
    def blocked(self) -> bool:
        return self.decision is Action.BLOCK


@dataclass(frozen=True, slots=True)
class FirewallPolicy:
    """Versioned rule/scope overrides with recommendation fallback."""

    policy_id: str
    version: str
    overrides: tuple[PolicyOverride, ...] = ()
    _index: Mapping[tuple[str, ScanScope], Action] = field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or not _IDENTIFIER.fullmatch(
            self.policy_id
        ):
            raise ValueError("policy_id must be a stable lowercase identifier")
        if not isinstance(self.version, str) or not _VERSION.fullmatch(self.version):
            raise ValueError("version must be a stable identifier")
        try:
            overrides = tuple(self.overrides)
        except TypeError as exc:
            raise TypeError("overrides must be iterable") from exc
        if any(not isinstance(item, PolicyOverride) for item in overrides):
            raise TypeError("overrides must contain PolicyOverride values")
        index: dict[tuple[str, ScanScope], Action] = {}
        for item in overrides:
            key = (item.rule_id, item.scope)
            if key in index:
                raise ValueError("policy contains a duplicate rule/scope override")
            index[key] = item.action
        object.__setattr__(self, "overrides", overrides)
        object.__setattr__(self, "_index", MappingProxyType(index))

    def action_for(self, finding: Finding, scope: ScanScope) -> Action:
        """Resolve an effective action without mutating the finding."""

        if not isinstance(finding, Finding):
            raise TypeError("finding must be a Finding")
        if not isinstance(scope, ScanScope):
            raise TypeError("scope must be a ScanScope")
        return self._index.get((finding.rule_id, scope), finding.action)

    def validate_rule_ids(self, rule_ids: frozenset[str]) -> None:
        """Fail closed when an override names a rule absent from the scanner."""

        if any(not isinstance(rule_id, str) for rule_id in rule_ids):
            raise TypeError("rule_ids must contain strings")
        unknown = sorted({item.rule_id for item in self.overrides} - rule_ids)
        if unknown:
            raise ValueError(f"policy contains unknown rule_id: {unknown[0]}")

    def apply(
        self,
        text: str,
        findings: tuple[Finding, ...],
        *,
        scope: ScanScope,
        redaction_text: str,
    ) -> FirewallResult:
        """Apply effective actions and return text that is safe to forward."""

        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if not isinstance(scope, ScanScope):
            raise TypeError("scope must be a ScanScope")
        if not isinstance(redaction_text, str) or not redaction_text:
            raise ValueError("redaction_text must be a non-empty string")
        try:
            selected = tuple(findings)
        except TypeError as exc:
            raise TypeError("findings must be iterable") from exc

        effective: list[Finding] = []
        for finding in selected:
            if not isinstance(finding, Finding):
                raise TypeError("findings must contain Finding instances")
            if finding.span.end > len(text):
                raise ValueError("finding span is outside text")
            effective.append(
                replace(finding, action=self.action_for(finding, scope))
            )
        effective_findings = tuple(effective)
        decision = max(
            (item.action for item in effective_findings),
            key=_ACTION_PRIORITY.__getitem__,
            default=Action.ALLOW,
        )
        if decision is Action.BLOCK:
            processed_text = None
        elif decision is Action.REDACT:
            processed_text = redact_findings(
                text,
                effective_findings,
                redaction_text,
            )
        else:
            processed_text = text
        return FirewallResult(
            policy_id=self.policy_id,
            policy_version=self.version,
            scope=scope,
            decision=decision,
            processed_text=processed_text,
            findings=effective_findings,
        )


def _secret_policy(
    policy_id: str,
    *,
    input_action: Action,
    output_action: Action,
) -> FirewallPolicy:
    return FirewallPolicy(
        policy_id=policy_id,
        version="1.0.0",
        overrides=(
            PolicyOverride("secrets.detected", ScanScope.INPUT, input_action),
            PolicyOverride("secrets.detected", ScanScope.OUTPUT, output_action),
        ),
    )


BALANCED_POLICY = _secret_policy(
    "llm_ffw.balanced",
    input_action=Action.REDACT,
    output_action=Action.REDACT,
)
STRICT_POLICY = _secret_policy(
    "llm_ffw.strict",
    input_action=Action.BLOCK,
    output_action=Action.REDACT,
)
AUDIT_POLICY = _secret_policy(
    "llm_ffw.audit",
    input_action=Action.REVIEW,
    output_action=Action.REVIEW,
)


class Firewall:
    """One-call direct scanner and policy-enforcement facade."""

    def __init__(
        self,
        *,
        scanner: Scanner | None = None,
        policy: FirewallPolicy = BALANCED_POLICY,
    ) -> None:
        if scanner is not None and not isinstance(scanner, Scanner):
            raise TypeError("scanner must be a Scanner or None")
        if not isinstance(policy, FirewallPolicy):
            raise TypeError("policy must be a FirewallPolicy")
        self._scanner = scanner or Scanner()
        policy.validate_rule_ids(
            frozenset(rule.rule_id for rule in self._scanner.rules)
        )
        self._policy = policy

    @property
    def scanner(self) -> Scanner:
        return self._scanner

    @property
    def policy(self) -> FirewallPolicy:
        return self._policy

    def process(
        self,
        text: str,
        *,
        scope: ScanScope = ScanScope.INPUT,
        prompt_context: str | None = None,
    ) -> FirewallResult:
        """Detect and enforce the configured action for each finding."""

        findings = self._scanner.scan(
            text,
            scope=scope,
            prompt_context=prompt_context,
        )
        return self._policy.apply(
            text,
            findings,
            scope=scope,
            redaction_text=self._scanner.config.redaction_text,
        )


__all__ = [
    "AUDIT_POLICY",
    "BALANCED_POLICY",
    "Firewall",
    "FirewallPolicy",
    "FirewallResult",
    "PolicyOverride",
    "STRICT_POLICY",
]
