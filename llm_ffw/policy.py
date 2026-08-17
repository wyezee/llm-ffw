"""Immutable policy enforcement for deterministic scanner findings."""

from dataclasses import dataclass, field, replace
from bisect import bisect_left, bisect_right
import re
from types import MappingProxyType
from typing import TYPE_CHECKING, Callable, Mapping

from .engine import Scanner
from .findings import Action, Finding, Span
from .inspection import ScanScope
from .rules.json_output import JSONOutputRule
from .redaction import sanitize_findings
from .stream_types import StreamMode

if TYPE_CHECKING:
    from .streaming import FirewallStream


_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?\Z")
_VERSION = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?\Z")
_ACTION_PRIORITY = {
    Action.ALLOW: 0,
    Action.REVIEW: 1,
    Action.REMOVE: 2,
    Action.REDACT: 3,
    Action.BLOCK: 4,
}


@dataclass(frozen=True, slots=True)
class _RemovalMap:
    text: str
    clean_positions: tuple[int, ...]
    cumulative_removed: tuple[int, ...]

    def original_span(self, span: Span) -> Span:
        start_index = bisect_right(self.clean_positions, span.start) - 1
        end_index = bisect_left(self.clean_positions, span.end) - 1
        start_shift = (
            self.cumulative_removed[start_index]
            if start_index >= 0
            else 0
        )
        end_shift = (
            self.cumulative_removed[end_index]
            if end_index >= 0
            else 0
        )
        return Span(span.start + start_shift, span.end + end_shift)


def _remove_effective_findings(
    text: str,
    findings: tuple[Finding, ...],
) -> _RemovalMap:
    spans = sorted(
        finding.span
        for finding in findings
        if finding.action is Action.REMOVE
    )
    merged: list[Span] = []
    for span in spans:
        if merged and span.start <= merged[-1].end:
            previous = merged[-1]
            merged[-1] = Span(previous.start, max(previous.end, span.end))
        else:
            merged.append(span)

    parts: list[str] = []
    clean_positions: list[int] = []
    cumulative_removed: list[int] = []
    cursor = 0
    removed = 0
    for span in merged:
        parts.append(text[cursor : span.start])
        clean_positions.append(span.start - removed)
        removed += span.end - span.start
        cumulative_removed.append(removed)
        cursor = span.end
    parts.append(text[cursor:])
    return _RemovalMap(
        text="".join(parts),
        clean_positions=tuple(clean_positions),
        cumulative_removed=tuple(cumulative_removed),
    )


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

    def validate_rule_ids(
        self,
        rule_ids: frozenset[str],
        *,
        supported_rule_ids: frozenset[str] | None = None,
    ) -> None:
        """Fail closed when an override names an unsupported rule."""

        if any(not isinstance(rule_id, str) for rule_id in rule_ids):
            raise TypeError("rule_ids must contain strings")
        supported = rule_ids if supported_rule_ids is None else supported_rule_ids
        if any(not isinstance(rule_id, str) for rule_id in supported):
            raise TypeError("supported_rule_ids must contain strings")
        if not rule_ids <= supported:
            raise ValueError("active rule IDs must be supported")
        unknown = sorted({item.rule_id for item in self.overrides} - supported)
        if unknown:
            raise ValueError(f"policy contains unknown rule_id: {unknown[0]}")
        invalid_json_actions = tuple(
            item.action
            for item in self.overrides
            if item.rule_id == "output.json.validity"
            and item.action not in (Action.BLOCK, Action.REVIEW)
        )
        if invalid_json_actions:
            raise ValueError(
                "output.json.validity policy action must be BLOCK or REVIEW"
            )

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

        effective_findings = self._effective_findings(selected, scope, len(text))
        return self._apply_effective(
            text,
            effective_findings,
            scope=scope,
            redaction_text=redaction_text,
        )

    def apply_with_rescan(
        self,
        text: str,
        findings: tuple[Finding, ...],
        *,
        scope: ScanScope,
        redaction_text: str,
        rescan: Callable[[str], tuple[Finding, ...]],
    ) -> FirewallResult:
        """Remove approved spans, rescan once, and enforce all findings."""

        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if not isinstance(scope, ScanScope):
            raise TypeError("scope must be a ScanScope")
        if not isinstance(redaction_text, str) or not redaction_text:
            raise ValueError("redaction_text must be a non-empty string")
        if not callable(rescan):
            raise TypeError("rescan must be callable")
        try:
            selected = tuple(findings)
        except TypeError as exc:
            raise TypeError("findings must be iterable") from exc
        effective = self._effective_findings(selected, scope, len(text))
        if any(item.action is Action.BLOCK for item in effective) or not any(
            item.action is Action.REMOVE for item in effective
        ):
            return self._apply_effective(
                text,
                effective,
                scope=scope,
                redaction_text=redaction_text,
            )

        removal_map = _remove_effective_findings(text, effective)
        rescanned = tuple(rescan(removal_map.text))
        mapped: list[Finding] = []
        for finding in rescanned:
            if not isinstance(finding, Finding):
                raise TypeError("rescan must return Finding instances")
            mapped.append(
                replace(
                    finding,
                    span=removal_map.original_span(finding.span),
                )
            )
        combined = tuple(
            sorted(
                (
                    *(item for item in effective if item.action is Action.REMOVE),
                    *mapped,
                ),
                key=lambda finding: (
                    finding.span.start,
                    finding.span.end,
                    finding.rule_id,
                    tuple(sorted(finding.metadata.items())),
                ),
            )
        )
        final_effective = self._effective_findings(combined, scope, len(text))
        return self._apply_effective(
            text,
            final_effective,
            scope=scope,
            redaction_text=redaction_text,
        )

    def _apply_staged_with_rescan(
        self,
        text: str,
        canonical_findings: tuple[Finding, ...],
        *,
        scope: ScanScope,
        redaction_text: str,
        scan_remaining: Callable[[str], tuple[Finding, ...]],
        rescan: Callable[[str], tuple[Finding, ...]],
    ) -> FirewallResult:
        """Skip the original non-canonical scan when removal triggers a rescan."""

        if not callable(scan_remaining):
            raise TypeError("scan_remaining must be callable")
        try:
            selected = tuple(canonical_findings)
        except TypeError as exc:
            raise TypeError("canonical_findings must be iterable") from exc
        actions = tuple(self.action_for(finding, scope) for finding in selected)
        if Action.BLOCK not in actions and Action.REMOVE in actions:
            findings = selected
        else:
            findings = tuple(
                sorted(
                    (*selected, *tuple(scan_remaining(text))),
                    key=lambda finding: (
                        finding.span.start,
                        finding.span.end,
                        finding.rule_id,
                        tuple(sorted(finding.metadata.items())),
                    ),
                )
            )
        return self.apply_with_rescan(
            text,
            findings,
            scope=scope,
            redaction_text=redaction_text,
            rescan=rescan,
        )

    def enforce_json_postcondition(
        self,
        text: str,
        result: FirewallResult,
        *,
        validator: JSONOutputRule | None,
        redaction_text: str,
    ) -> FirewallResult:
        """Revalidate only transformed JSON output and block unsafe results."""

        if validator is None:
            return result
        if not isinstance(validator, JSONOutputRule):
            raise TypeError("validator must be a JSONOutputRule or None")
        if not isinstance(result, FirewallResult):
            raise TypeError("result must be a FirewallResult")
        if (
            result.blocked
            or result.scope is not ScanScope.OUTPUT
            or result.processed_text == text
        ):
            return result
        if result.processed_text is None:
            raise RuntimeError("non-blocked result has no processed text")
        matches = validator.scan_text(result.processed_text)
        if not matches:
            return result
        postcondition_findings = tuple(
            Finding(
                rule_id=validator.rule_id,
                severity=match.severity,
                action=match.action,
                span=Span(0, 0),
                message=match.message,
                redacted_preview=match.redacted_preview,
                metadata={
                    **dict(match.metadata),
                    "validation_phase": "post_policy",
                },
            )
            for match in matches
        )
        return self.apply(
            text,
            (*result.findings, *postcondition_findings),
            scope=result.scope,
            redaction_text=redaction_text,
        )

    def _effective_findings(
        self,
        findings: tuple[Finding, ...],
        scope: ScanScope,
        text_length: int,
    ) -> tuple[Finding, ...]:
        effective: list[Finding] = []
        for finding in findings:
            if not isinstance(finding, Finding):
                raise TypeError("findings must contain Finding instances")
            if finding.span.end > text_length:
                raise ValueError("finding span is outside text")
            effective.append(
                replace(finding, action=self.action_for(finding, scope))
            )
        return tuple(effective)

    def _apply_effective(
        self,
        text: str,
        effective_findings: tuple[Finding, ...],
        *,
        scope: ScanScope,
        redaction_text: str,
    ) -> FirewallResult:
        decision = max(
            (item.action for item in effective_findings),
            key=_ACTION_PRIORITY.__getitem__,
            default=Action.ALLOW,
        )
        if decision is Action.BLOCK:
            processed_text = None
        elif decision in (Action.REMOVE, Action.REDACT):
            processed_text = sanitize_findings(
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


def _builtin_policy(
    policy_id: str,
    *,
    input_action: Action,
    output_action: Action,
    invisible_action: Action | None,
    unicode_tag_action: Action | None,
    json_output_action: Action,
    unsafe_url_action: Action,
    ip_address_action: Action,
    mac_address_action: Action,
    iban_action: Action,
    authorization_header_action: Action,
    email_address_action: Action,
    payment_card_action: Action,
    private_key_action: Action,
    jwt_token_action: Action,
) -> FirewallPolicy:
    invisible_overrides = (
        (
            PolicyOverride(
                "unicode.invisible_characters",
                ScanScope.INPUT,
                invisible_action,
            ),
        )
        if invisible_action is not None
        else ()
    )
    unicode_tag_overrides = (
        (
            PolicyOverride(
                "unicode.tag_smuggling",
                ScanScope.INPUT,
                unicode_tag_action,
            ),
        )
        if unicode_tag_action is not None
        else ()
    )
    return FirewallPolicy(
        policy_id=policy_id,
        version="1.12.0",
        overrides=(
            PolicyOverride("secrets.detected", ScanScope.INPUT, input_action),
            PolicyOverride("secrets.detected", ScanScope.OUTPUT, output_action),
            *invisible_overrides,
            *unicode_tag_overrides,
            PolicyOverride(
                "output.json.validity",
                ScanScope.OUTPUT,
                json_output_action,
            ),
            PolicyOverride(
                "url.unsafe",
                ScanScope.INPUT,
                unsafe_url_action,
            ),
            PolicyOverride(
                "url.unsafe",
                ScanScope.OUTPUT,
                unsafe_url_action,
            ),
            PolicyOverride(
                "pii.ip_address",
                ScanScope.INPUT,
                ip_address_action,
            ),
            PolicyOverride(
                "pii.ip_address",
                ScanScope.OUTPUT,
                ip_address_action,
            ),
            PolicyOverride(
                "pii.mac_address",
                ScanScope.INPUT,
                mac_address_action,
            ),
            PolicyOverride(
                "pii.mac_address",
                ScanScope.OUTPUT,
                mac_address_action,
            ),
            PolicyOverride(
                "pii.iban",
                ScanScope.INPUT,
                iban_action,
            ),
            PolicyOverride(
                "pii.iban",
                ScanScope.OUTPUT,
                iban_action,
            ),
            PolicyOverride(
                "secrets.authorization_header",
                ScanScope.INPUT,
                authorization_header_action,
            ),
            PolicyOverride(
                "secrets.authorization_header",
                ScanScope.OUTPUT,
                authorization_header_action,
            ),
            PolicyOverride(
                "pii.email_address",
                ScanScope.INPUT,
                email_address_action,
            ),
            PolicyOverride(
                "pii.email_address",
                ScanScope.OUTPUT,
                email_address_action,
            ),
            PolicyOverride(
                "pii.payment_card",
                ScanScope.INPUT,
                payment_card_action,
            ),
            PolicyOverride(
                "pii.payment_card",
                ScanScope.OUTPUT,
                payment_card_action,
            ),
            PolicyOverride(
                "secrets.private_key",
                ScanScope.INPUT,
                private_key_action,
            ),
            PolicyOverride(
                "secrets.jwt_token",
                ScanScope.INPUT,
                jwt_token_action,
            ),
            PolicyOverride(
                "secrets.jwt_token",
                ScanScope.OUTPUT,
                jwt_token_action,
            ),
            PolicyOverride(
                "secrets.private_key",
                ScanScope.OUTPUT,
                private_key_action,
            ),
        ),
    )


BALANCED_POLICY = _builtin_policy(
    "llm_ffw.balanced",
    input_action=Action.REDACT,
    output_action=Action.REDACT,
    invisible_action=None,
    unicode_tag_action=None,
    json_output_action=Action.BLOCK,
    unsafe_url_action=Action.REDACT,
    ip_address_action=Action.REDACT,
    mac_address_action=Action.REDACT,
    iban_action=Action.REDACT,
    authorization_header_action=Action.REDACT,
    email_address_action=Action.REDACT,
    payment_card_action=Action.REDACT,
    private_key_action=Action.REDACT,
    jwt_token_action=Action.REDACT,
)
STRICT_POLICY = _builtin_policy(
    "llm_ffw.strict",
    input_action=Action.BLOCK,
    output_action=Action.REDACT,
    invisible_action=Action.BLOCK,
    unicode_tag_action=Action.BLOCK,
    json_output_action=Action.BLOCK,
    unsafe_url_action=Action.BLOCK,
    ip_address_action=Action.BLOCK,
    mac_address_action=Action.BLOCK,
    iban_action=Action.BLOCK,
    authorization_header_action=Action.BLOCK,
    email_address_action=Action.BLOCK,
    payment_card_action=Action.BLOCK,
    private_key_action=Action.BLOCK,
    jwt_token_action=Action.BLOCK,
)
AUDIT_POLICY = _builtin_policy(
    "llm_ffw.audit",
    input_action=Action.REVIEW,
    output_action=Action.REVIEW,
    invisible_action=Action.REVIEW,
    unicode_tag_action=Action.REVIEW,
    json_output_action=Action.REVIEW,
    unsafe_url_action=Action.REVIEW,
    ip_address_action=Action.REVIEW,
    mac_address_action=Action.REVIEW,
    iban_action=Action.REVIEW,
    authorization_header_action=Action.REVIEW,
    email_address_action=Action.REVIEW,
    payment_card_action=Action.REVIEW,
    private_key_action=Action.REVIEW,
    jwt_token_action=Action.REVIEW,
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
            frozenset(rule.rule_id for rule in self._scanner.rules),
            supported_rule_ids=frozenset(
                (
                    "secrets.detected",
                    "unicode.invisible_characters",
                    "unicode.tag_smuggling",
                    "output.json.validity",
                    "url.unsafe",
                    "pii.ip_address",
                    "pii.mac_address",
                    "pii.iban",
                    "secrets.authorization_header",
                    "pii.email_address",
                    "pii.payment_card",
                    "secrets.private_key",
                    "secrets.jwt_token",
                    *(rule.rule_id for rule in self._scanner.rules),
                )
            ),
        )
        self._policy = policy
        self._json_output_rule = next(
            (
                rule
                for rule in self._scanner.rules
                if isinstance(rule, JSONOutputRule)
            ),
            None,
        )

    @property
    def scanner(self) -> Scanner:
        return self._scanner

    @property
    def policy(self) -> FirewallPolicy:
        return self._policy

    def stream(
        self,
        *,
        scope: ScanScope = ScanScope.INPUT,
        mode: StreamMode = StreamMode.AUTO,
        prompt_context: str | None = None,
    ) -> "FirewallStream":
        """Create a unified stream using this firewall's scanner and policy."""

        from .streaming import FirewallStream

        return FirewallStream(
            scanner=self._scanner,
            policy=self._policy,
            scope=scope,
            mode=mode,
            prompt_context=prompt_context,
        )

    def process(
        self,
        text: str,
        *,
        scope: ScanScope = ScanScope.INPUT,
        prompt_context: str | None = None,
    ) -> FirewallResult:
        """Detect and enforce the configured action for each finding."""

        if (
            type(self._scanner) is not Scanner
            or not self._scanner._supports_staged_canonicalization
        ):
            findings = self._scanner.scan(
                text,
                scope=scope,
                prompt_context=prompt_context,
            )
            result = self._policy.apply_with_rescan(
                text,
                findings,
                scope=scope,
                redaction_text=self._scanner.config.redaction_text,
                rescan=lambda cleaned: self._scanner.scan(
                    cleaned,
                    scope=scope,
                    prompt_context=prompt_context,
                ),
            )
            return self._policy.enforce_json_postcondition(
                text,
                result,
                validator=self._json_output_rule,
                redaction_text=self._scanner.config.redaction_text,
            )

        canonical_findings = self._scanner._scan_canonicalizers(
            text,
            scope=scope,
            prompt_context=prompt_context,
        )
        result = self._policy._apply_staged_with_rescan(
            text,
            canonical_findings,
            scope=scope,
            redaction_text=self._scanner.config.redaction_text,
            scan_remaining=lambda original: self._scanner._scan_remaining(
                original,
                scope=scope,
                prompt_context=prompt_context,
            ),
            rescan=lambda cleaned: self._scanner.scan(
                cleaned,
                scope=scope,
                prompt_context=prompt_context,
            ),
        )
        return self._policy.enforce_json_postcondition(
            text,
            result,
            validator=self._json_output_rule,
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
