"""Unified streaming contract with explicit rule compatibility."""

from typing import cast

from .engine import RuleScanner
from .facade import ContentBlockedError
from .findings import Action, Finding, Severity, Span
from .inspection import ScanScope
from .policy import BALANCED_POLICY, FirewallPolicy, RuleEngine
from .rules.payment_card import PaymentCardRule
from .rules.base import Rule
from .rules.secrets import SecretsRule
from ._incremental_stream import _IncrementalRedactionEngine
from ._payment_card_stream import _PaymentCardStreamDetector
from ._stream_coordinator import _IncrementalStreamCoordinator
from .stream_types import (
    FirewallStreamState,
    IncrementalStreamingUnavailableError,
    StreamingRuleCapability,
    StreamingSupport,
    StreamMode,
)


class FirewallStream:
    """Accept text chunks while preserving configured firewall semantics.

    ``AUTO`` selects incremental execution only when every active rule and
    effective action can safely emit early. Otherwise it buffers until
    ``finish()`` and invokes the normal :class:`RuleEngine`. ``INCREMENTAL``
    rejects incompatible configurations instead of silently omitting rules.
    Instances are stateful and must not be shared by concurrent callers.
    """

    __slots__ = (
        "_buffered_parts",
        "_buffered_chars",
        "_decision",
        "_engine",
        "_execution_mode",
        "_findings",
        "_firewall",
        "_max_buffered_chars",
        "_max_input_chars",
        "_prompt_context",
        "_received_chars",
        "_requested_mode",
        "_rule_capabilities",
        "_scope",
        "_state",
    )

    def __init__(
        self,
        *,
        scanner: RuleScanner | None = None,
        policy: FirewallPolicy = BALANCED_POLICY,
        scope: ScanScope = ScanScope.INPUT,
        mode: StreamMode = StreamMode.AUTO,
        prompt_context: str | None = None,
    ) -> None:
        if scanner is not None and not isinstance(scanner, RuleScanner):
            raise TypeError("scanner must be a RuleScanner or None")
        selected_scanner = scanner or RuleScanner()
        if not isinstance(policy, FirewallPolicy):
            raise TypeError("policy must be a FirewallPolicy")
        if not isinstance(scope, ScanScope):
            raise TypeError("scope must be a ScanScope")
        if not isinstance(mode, StreamMode):
            raise TypeError("mode must be a StreamMode")
        if prompt_context is not None and not isinstance(prompt_context, str):
            raise TypeError("prompt_context must be a string or None")
        if scope is ScanScope.INPUT and prompt_context is not None:
            raise ValueError("prompt_context is only valid for output streams")
        if (
            prompt_context is not None
            and len(prompt_context) > selected_scanner.config.max_input_chars
        ):
            raise ValueError("prompt_context exceeds max_input_chars")

        firewall = RuleEngine(scanner=selected_scanner, policy=policy)
        active_rules = tuple(
            rule for rule in selected_scanner.rules if scope in rule.scopes
        )
        capabilities = [
            self._capability_for(rule)
            for rule in active_rules
        ]
        incompatible = {
            item.rule_id
            for item in capabilities
            if item.support is not StreamingSupport.INCREMENTAL
        }
        secret_rule = next(
            (
                rule
                for rule in active_rules
                if type(rule) is SecretsRule
            ),
            None,
        )
        payment_card_rule = next(
            (
                rule
                for rule in active_rules
                if type(rule) is PaymentCardRule
            ),
            None,
        )
        if secret_rule is not None and not self._secret_actions_are_redacting(
            secret_rule,
            policy,
            scope,
        ):
            incompatible.add(secret_rule.rule_id)
            capabilities = self._replace_capability(
                capabilities,
                secret_rule.rule_id,
                "effective policy action requires end-of-stream enforcement",
            )
        if payment_card_rule is not None and not self._actions_are_redacting(
            payment_card_rule.rule_id,
            (Action.REDACT, Action.BLOCK),
            policy,
            scope,
        ):
            incompatible.add(payment_card_rule.rule_id)
            capabilities = self._replace_capability(
                capabilities,
                payment_card_rule.rule_id,
                "effective policy action requires end-of-stream enforcement",
            )
        if type(selected_scanner) is not RuleScanner:
            incompatible.add("scanner.custom")
            capabilities = [
                StreamingRuleCapability(
                    rule_id=item.rule_id,
                    support=StreamingSupport.END_OF_STREAM,
                    reason="custom scanner semantics require end-of-stream execution",
                )
                for item in capabilities
            ]

        if mode is StreamMode.INCREMENTAL and incompatible:
            raise IncrementalStreamingUnavailableError(tuple(incompatible))
        execution_mode = (
            StreamMode.BUFFERED
            if mode is StreamMode.BUFFERED or incompatible
            else StreamMode.INCREMENTAL
        )

        engine = None
        if execution_mode is StreamMode.INCREMENTAL and (
            secret_rule is not None or payment_card_rule is not None
        ):
            try:
                redaction_engine = _IncrementalRedactionEngine(
                    catalog=(
                        secret_rule.catalog
                        if secret_rule is not None
                        else None
                    ),
                    max_input_chars=selected_scanner.config.max_input_chars,
                    redaction_text=selected_scanner.config.redaction_text,
                )
                engine = _IncrementalStreamCoordinator(
                    engine=redaction_engine,
                    payment_detector=(
                        _PaymentCardStreamDetector(payment_card_rule)
                        if payment_card_rule is not None
                        else None
                    ),
                )
            except ValueError:
                if secret_rule is not None:
                    incompatible_rule_id = secret_rule.rule_id
                elif payment_card_rule is not None:
                    incompatible_rule_id = payment_card_rule.rule_id
                else:
                    raise RuntimeError("incremental detector rule is missing")
                if mode is StreamMode.INCREMENTAL:
                    raise IncrementalStreamingUnavailableError(
                        (incompatible_rule_id,)
                    ) from None
                execution_mode = StreamMode.BUFFERED
                capabilities = self._replace_capability(
                    capabilities,
                    incompatible_rule_id,
                    "catalog shape requires end-of-stream execution",
                )

        self._firewall = firewall
        self._scope = scope
        self._requested_mode = mode
        self._execution_mode = execution_mode
        self._prompt_context = prompt_context
        self._max_input_chars = selected_scanner.config.max_input_chars
        self._engine = engine
        self._buffered_parts: list[str] = []
        self._buffered_chars = 0
        self._received_chars = 0
        self._max_buffered_chars = 0
        self._findings: tuple[Finding, ...] = ()
        self._decision: Action | None = None
        self._rule_capabilities = tuple(capabilities)
        self._state = FirewallStreamState.OPEN

    @property
    def state(self) -> FirewallStreamState:
        """Return the current lifecycle state."""

        return self._state

    @property
    def requested_mode(self) -> StreamMode:
        """Return the mode requested by the caller."""

        return self._requested_mode

    @property
    def execution_mode(self) -> StreamMode:
        """Return the resolved incremental or buffered execution mode."""

        return self._execution_mode

    @property
    def scope(self) -> ScanScope:
        """Return the fixed scan direction for this stream."""

        return self._scope

    @property
    def policy_id(self) -> str:
        """Return the pinned policy identifier."""

        return self._firewall.policy.policy_id

    @property
    def policy_version(self) -> str:
        """Return the pinned policy version."""

        return self._firewall.policy.version

    @property
    def rule_capabilities(self) -> tuple[StreamingRuleCapability, ...]:
        """Return support metadata for rules active in this stream's scope."""

        return self._rule_capabilities

    @property
    def findings(self) -> tuple[Finding, ...]:
        """Return completed disclosure-safe findings in original source order."""

        if self._engine is not None and self._state is FirewallStreamState.OPEN:
            return self._engine.findings
        return self._findings

    @property
    def decision(self) -> Action | None:
        """Return the final decision, or ``None`` before successful finish."""

        return self._decision

    @property
    def received_chars(self) -> int:
        """Return the cumulative accepted character count."""

        return self._received_chars

    @property
    def buffered_chars(self) -> int:
        """Return the currently retained source character count."""

        if self._engine is not None:
            return self._engine.buffered_chars
        return self._buffered_chars

    @property
    def max_buffered_chars(self) -> int:
        """Return the peak retained source character count."""

        if self._engine is not None:
            return self._engine.max_buffered_chars
        return self._max_buffered_chars

    def feed(self, chunk: str) -> str:
        """Accept one non-empty chunk and return text safe to emit now."""

        self._require_open()
        if not isinstance(chunk, str):
            raise TypeError("chunk must be a string")
        if not chunk:
            raise ValueError("chunk must not be empty")
        new_total = self._received_chars + len(chunk)
        if new_total > self._max_input_chars:
            self.cancel()
            raise ValueError("stream exceeds max_input_chars")
        self._received_chars = new_total
        try:
            if self._execution_mode is StreamMode.BUFFERED:
                self._buffered_parts.append(chunk)
                self._buffered_chars = self._received_chars
                self._max_buffered_chars = max(
                    self._max_buffered_chars,
                    self._received_chars,
                )
                return ""
            if self._engine is None:
                return chunk
            return self._engine.feed(chunk)
        except BaseException:
            self.cancel()
            raise

    def finish(self) -> str:
        """Finalize enforcement and return the remaining forwardable text."""

        self._require_open()
        try:
            if self._execution_mode is StreamMode.BUFFERED:
                text = "".join(self._buffered_parts)
                self._buffered_parts.clear()
                self._buffered_chars = 0
                prompt_context = self._prompt_context
                self._prompt_context = None
                result = self._firewall.process(
                    text,
                    scope=self._scope,
                    prompt_context=prompt_context,
                )
                self._findings = result.findings
                self._decision = result.decision
                self._state = FirewallStreamState.FINISHED
                if result.blocked:
                    raise ContentBlockedError(result)
                return cast(str, result.processed_text)

            if self._engine is None:
                tail = ""
                findings: tuple[Finding, ...] = ()
            else:
                tail = self._engine.finish()
                findings = self._engine.findings
            self._prompt_context = None
            self._findings = findings
            self._decision = max(
                (finding.action for finding in findings),
                key=self._action_priority,
                default=Action.ALLOW,
            )
            self._state = FirewallStreamState.FINISHED
            return tail
        except BaseException:
            self.cancel()
            raise

    def cancel(self) -> None:
        """Cancel an open stream and release retained source text."""

        if self._state is FirewallStreamState.OPEN:
            self._buffered_parts.clear()
            self._buffered_chars = 0
            self._prompt_context = None
            if self._engine is not None:
                self._engine.cancel()
            self._state = FirewallStreamState.CANCELLED

    def _require_open(self) -> None:
        if self._state is not FirewallStreamState.OPEN:
            raise RuntimeError("stream is not open")

    @staticmethod
    def _capability_for(rule: Rule) -> StreamingRuleCapability:
        if type(rule) in (SecretsRule, PaymentCardRule):
            incremental_rule = cast(SecretsRule | PaymentCardRule, rule)
            return StreamingRuleCapability(
                rule_id=incremental_rule.rule_id,
                support=StreamingSupport.INCREMENTAL,
                reason="fused incremental detector available",
            )
        return StreamingRuleCapability(
            rule_id=rule.rule_id,
            support=StreamingSupport.END_OF_STREAM,
            reason="complete-document execution required in this release",
        )

    @staticmethod
    def _replace_capability(
        capabilities: list[StreamingRuleCapability],
        rule_id: str,
        reason: str,
    ) -> list[StreamingRuleCapability]:
        return [
            StreamingRuleCapability(
                rule_id=item.rule_id,
                support=StreamingSupport.END_OF_STREAM,
                reason=reason,
            )
            if item.rule_id == rule_id
            else item
            for item in capabilities
        ]

    @staticmethod
    def _secret_actions_are_redacting(
        rule: SecretsRule,
        policy: FirewallPolicy,
        scope: ScanScope,
    ) -> bool:
        return FirewallStream._actions_are_redacting(
            rule.rule_id,
            (
                *(signature.action for signature in rule.catalog.signatures),
                Action.BLOCK,
            ),
            policy,
            scope,
        )

    @staticmethod
    def _actions_are_redacting(
        rule_id: str,
        recommended_actions: tuple[Action, ...],
        policy: FirewallPolicy,
        scope: ScanScope,
    ) -> bool:
        for action in recommended_actions:
            representative = Finding(
                rule_id=rule_id,
                severity=Severity.HIGH,
                action=action,
                span=Span(0, 0),
                message="Streaming compatibility probe.",
            )
            if policy.action_for(representative, scope) is not Action.REDACT:
                return False
        return True

    @staticmethod
    def _action_priority(action: Action) -> int:
        return {
            Action.ALLOW: 0,
            Action.REVIEW: 1,
            Action.REMOVE: 2,
            Action.REDACT: 3,
            Action.BLOCK: 4,
        }[action]


__all__ = [
    "FirewallStream",
    "FirewallStreamState",
    "IncrementalStreamingUnavailableError",
    "StreamingRuleCapability",
    "StreamingSupport",
    "StreamMode",
]
