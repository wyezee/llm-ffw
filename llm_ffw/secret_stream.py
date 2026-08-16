"""Incremental, redacting inspection for constrained secret signatures."""

from dataclasses import dataclass
from enum import Enum
import re

from .findings import Action, Finding, Severity, Span
from .rules.secrets import SecretsRule
from .secret_catalog import (
    SecretCatalog,
    SecretSignature,
    _resolve_secret_catalog,
)


class SecretStreamState(str, Enum):
    """Lifecycle state of a :class:`SecretStream`."""

    OPEN = "open"
    FINISHED = "finished"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class _PlannedMatch:
    start: int
    end: int
    finding: Finding


@dataclass(frozen=True, slots=True)
class _UnboundedCandidate:
    start: int
    end: int
    signature: SecretSignature
    last_char: str


@dataclass(frozen=True, slots=True)
class _SegmentPlan:
    safe_end: int
    matches: tuple[_PlannedMatch, ...]
    unbounded: _UnboundedCandidate | None = None
    overflow_start: int | None = None


class SecretStream:
    """Redact catalog-shaped secrets while text arrives in chunks.

    This specialized API runs only ``SecretsRule``-equivalent inspection. It
    does not represent that other firewall rules inspected the stream. Catalog
    actions must be ``REDACT`` because already-emitted text cannot be recalled.
    Instances are stateful and must not be shared between concurrent callers.
    """

    MAX_PENDING_CANDIDATE_CHARS = 65_536

    __slots__ = (
        "_active_unbounded",
        "_catalog",
        "_findings",
        "_max_buffered_chars",
        "_max_input_chars",
        "_max_prefix_chars",
        "_overflow_finding_added",
        "_overflow_start",
        "_partial_owners",
        "_pending",
        "_pending_offset",
        "_prefix_pattern",
        "_previous_char",
        "_received_chars",
        "_redaction_text",
        "_signatures_by_prefix",
        "_state",
    )

    def __init__(
        self,
        *,
        additional_secret_catalog: SecretCatalog | None = None,
        replacement_secret_catalog: SecretCatalog | None = None,
        max_input_chars: int = 8_000_000,
        redaction_text: str = "[REDACTED]",
    ) -> None:
        catalog = _resolve_secret_catalog(
            additional_secret_catalog,
            replacement_secret_catalog,
        )
        if any(
            signature.action is not Action.REDACT
            for signature in catalog.signatures
        ):
            raise ValueError("SecretStream supports REDACT secret actions only")
        for signature in catalog.signatures:
            if signature.max_suffix_chars is None and (
                signature.suffix_ending
                or set(signature.boundary_chars) != set(signature.suffix_chars)
            ):
                raise ValueError(
                    "unbounded signatures require identical suffix/boundary "
                    "characters and no suffix ending"
                )
            if (
                signature.max_suffix_chars is not None
                and signature.max_suffix_chars
                > self.MAX_PENDING_CANDIDATE_CHARS
            ):
                raise ValueError(
                    "bounded signatures must not exceed "
                    f"{self.MAX_PENDING_CANDIDATE_CHARS} suffix characters"
                )
        if (
            isinstance(max_input_chars, bool)
            or not isinstance(max_input_chars, int)
        ):
            raise TypeError("max_input_chars must be an integer")
        if max_input_chars <= 0:
            raise ValueError("max_input_chars must be positive")
        if not isinstance(redaction_text, str):
            raise TypeError("redaction_text must be a string")
        if not redaction_text:
            raise ValueError("redaction_text must not be empty")

        entries = tuple(
            sorted(
                (
                    (prefix, signature)
                    for signature in catalog.signatures
                    for prefix in signature.prefixes
                ),
                key=lambda item: (-len(item[0]), item[0]),
            )
        )
        alternatives = "|".join(re.escape(prefix) for prefix, _ in entries)
        self._prefix_pattern = re.compile(f"({alternatives})", re.ASCII)
        self._signatures_by_prefix = dict(entries)
        partial_owners: dict[str, list[SecretSignature]] = {}
        for prefix, signature in entries:
            for length in range(1, len(prefix)):
                partial_owners.setdefault(prefix[:length], []).append(signature)
        self._partial_owners = {
            fragment: tuple(owners)
            for fragment, owners in partial_owners.items()
        }
        self._max_prefix_chars = max(len(prefix) for prefix, _ in entries)

        self._catalog = catalog
        self._max_input_chars = max_input_chars
        self._redaction_text = redaction_text
        self._pending = ""
        self._pending_offset = 0
        self._previous_char = ""
        self._active_unbounded: _UnboundedCandidate | None = None
        self._overflow_start: int | None = None
        self._overflow_finding_added = False
        self._received_chars = 0
        self._max_buffered_chars = 0
        self._findings: list[Finding] = []
        self._state = SecretStreamState.OPEN

    @property
    def state(self) -> SecretStreamState:
        """Return the current stream lifecycle state."""

        return self._state

    @property
    def catalog(self) -> SecretCatalog:
        """Return the immutable catalog pinned to this stream."""

        return self._catalog

    @property
    def findings(self) -> tuple[Finding, ...]:
        """Return completed disclosure-safe findings in source order."""

        return tuple(self._findings)

    @property
    def received_chars(self) -> int:
        """Return the number of characters accepted by this stream."""

        return self._received_chars

    @property
    def buffered_chars(self) -> int:
        """Return the currently retained undecided character count."""

        return len(self._pending)

    @property
    def max_buffered_chars(self) -> int:
        """Return the peak retained undecided character count."""

        return self._max_buffered_chars

    def feed(self, chunk: str) -> str:
        """Inspect one non-empty chunk and return text safe to forward now."""

        self._require_open()
        if not isinstance(chunk, str):
            raise TypeError("chunk must be a string")
        if not chunk:
            raise ValueError("chunk must not be empty")
        new_total = self._received_chars + len(chunk)
        if new_total > self._max_input_chars:
            self.cancel()
            raise ValueError("stream exceeds max_input_chars")
        chunk_start = self._received_chars
        self._received_chars = new_total
        try:
            return self._consume(chunk, chunk_start=chunk_start)
        except BaseException:
            self.cancel()
            raise

    def finish(self) -> str:
        """Resolve end-of-stream state and return the final safe text."""

        self._require_open()
        try:
            parts: list[str] = []
            if self._overflow_start is not None:
                self._add_overflow_finding()
            elif self._active_unbounded is not None:
                self._complete_unbounded(self._received_chars)
            elif self._pending:
                plan = self._plan_segment(self._pending, final=True)
                parts.append(self._apply_plan(self._pending, plan))
                self._pending = ""
            self._state = SecretStreamState.FINISHED
            return "".join(parts)
        except BaseException:
            self.cancel()
            raise

    def cancel(self) -> None:
        """Cancel an open stream and release retained source text."""

        if self._state is SecretStreamState.OPEN:
            self._pending = ""
            self._previous_char = ""
            self._active_unbounded = None
            self._state = SecretStreamState.CANCELLED

    def _require_open(self) -> None:
        if self._state is not SecretStreamState.OPEN:
            raise RuntimeError("stream is not open")

    def _consume(self, chunk: str, *, chunk_start: int) -> str:
        if self._overflow_start is not None:
            return ""
        if self._active_unbounded is not None:
            return self._consume_unbounded(chunk, chunk_start=chunk_start)

        if self._pending:
            text = self._pending + chunk
            base_offset = self._pending_offset
        else:
            text = chunk
            base_offset = chunk_start
        self._pending_offset = base_offset
        self._pending = text
        self._max_buffered_chars = max(
            self._max_buffered_chars,
            len(self._pending),
        )
        plan = self._plan_segment(text, final=False)
        return self._apply_plan(text, plan)

    def _consume_unbounded(self, chunk: str, *, chunk_start: int) -> str:
        active = self._active_unbounded
        if active is None:
            raise RuntimeError("unbounded candidate state is missing")
        end = 0
        suffix_chars = active.signature.suffix_chars
        while end < len(chunk) and chunk[end] in suffix_chars:
            end += 1
        active = _UnboundedCandidate(
            start=active.start,
            end=chunk_start + end,
            signature=active.signature,
            last_char=chunk[end - 1] if end else active.last_char,
        )
        self._active_unbounded = active
        if end == len(chunk):
            return ""
        self._complete_unbounded(active.end)
        self._previous_char = active.last_char
        return self._consume(chunk[end:], chunk_start=chunk_start + end)

    def _complete_unbounded(self, end: int) -> None:
        active = self._active_unbounded
        if active is None:
            raise RuntimeError("unbounded candidate state is missing")
        self._findings.append(
            self._secret_finding(active.signature, active.start, end)
        )
        self._active_unbounded = None

    def _plan_segment(self, text: str, *, final: bool) -> _SegmentPlan:
        matches: list[_PlannedMatch] = []
        next_position = 0
        for prefix_match in self._prefix_pattern.finditer(text):
            position = prefix_match.start()
            if position < next_position:
                continue
            prefix = prefix_match.group(1)
            signature = self._signatures_by_prefix[prefix]
            previous = text[position - 1] if position else self._previous_char
            if previous and previous in signature.boundary_chars:
                continue

            prefix_end = position + len(prefix)
            match_end = prefix_end
            suffix_length = 0
            while match_end < len(text) and text[match_end] in signature.suffix_chars:
                match_end += 1
                suffix_length += 1
                maximum = signature.max_suffix_chars
                if maximum is not None and suffix_length > maximum:
                    break

            maximum = signature.max_suffix_chars
            unresolved = match_end == len(text) and (
                maximum is None or suffix_length <= maximum
            )
            if unresolved and not final:
                if (
                    maximum is None
                    and suffix_length >= signature.min_suffix_chars
                ):
                    return _SegmentPlan(
                        safe_end=position,
                        matches=tuple(matches),
                        unbounded=_UnboundedCandidate(
                            start=self._pending_offset + position,
                            end=self._pending_offset + match_end,
                            signature=signature,
                            last_char=text[match_end - 1],
                        ),
                    )
                return _SegmentPlan(position, tuple(matches))

            valid_length = (
                suffix_length >= signature.min_suffix_chars
                and (maximum is None or suffix_length <= maximum)
            )
            valid_boundary = (
                match_end == len(text)
                or text[match_end] not in signature.boundary_chars
            )
            valid_ending = (
                not signature.suffix_ending
                or text.endswith(
                    signature.suffix_ending,
                    prefix_end,
                    match_end,
                )
            )
            if not (valid_length and valid_boundary and valid_ending):
                continue

            absolute_start = self._pending_offset + position
            absolute_end = self._pending_offset + match_end
            if len(self._findings) + len(matches) >= SecretsRule.MAX_CANDIDATES:
                return _SegmentPlan(
                    safe_end=position,
                    matches=tuple(matches),
                    overflow_start=absolute_start,
                )
            matches.append(
                _PlannedMatch(
                    position,
                    match_end,
                    self._secret_finding(
                        signature,
                        absolute_start,
                        absolute_end,
                    ),
                )
            )
            next_position = match_end

        if not final:
            partial_start = self._trailing_partial_start(text)
            if partial_start is not None:
                return _SegmentPlan(partial_start, tuple(matches))
        return _SegmentPlan(len(text), tuple(matches))

    def _trailing_partial_start(self, text: str) -> int | None:
        maximum = min(len(text), self._max_prefix_chars - 1)
        for length in range(maximum, 0, -1):
            fragment = text[-length:]
            owners = self._partial_owners.get(fragment)
            if owners is None:
                continue
            position = len(text) - length
            previous = text[position - 1] if position else self._previous_char
            if any(
                not previous or previous not in signature.boundary_chars
                for signature in owners
            ):
                return position
        return None

    def _apply_plan(self, text: str, plan: _SegmentPlan) -> str:
        parts: list[str] = []
        cursor = 0
        for match in plan.matches:
            parts.append(text[cursor : match.start])
            parts.append(self._redaction_text)
            cursor = match.end
            self._findings.append(match.finding)
        parts.append(text[cursor : plan.safe_end])
        emission = "".join(parts)

        if plan.safe_end:
            self._previous_char = text[plan.safe_end - 1]
        self._pending = text[plan.safe_end:]
        self._pending_offset += plan.safe_end

        if plan.overflow_start is not None:
            self._overflow_start = plan.overflow_start
            self._pending = ""
            parts.append(self._redaction_text)
            emission = "".join(parts)
        elif plan.unbounded is not None:
            if len(self._findings) >= SecretsRule.MAX_CANDIDATES:
                self._overflow_start = plan.unbounded.start
            else:
                self._active_unbounded = plan.unbounded
            self._pending = ""
            emission += self._redaction_text
        return emission

    def _add_overflow_finding(self) -> None:
        if self._overflow_finding_added:
            return
        start = self._overflow_start
        if start is None:
            raise RuntimeError("overflow state is missing")
        self._findings.append(
            Finding(
                rule_id=SecretsRule.RULE_ID,
                severity=Severity.HIGH,
                action=Action.REDACT,
                span=Span(start, self._received_chars),
                message="Secret inspection limit exceeded.",
                metadata={
                    "reason": "candidate_limit_exceeded",
                    "limit": str(SecretsRule.MAX_CANDIDATES),
                    "catalog_id": self._catalog.catalog_id,
                    "catalog_version": self._catalog.version,
                    "detector": "well_known_prefix",
                    "span_basis": "characters",
                },
            )
        )
        self._overflow_finding_added = True

    def _secret_finding(
        self,
        signature: SecretSignature,
        start: int,
        end: int,
    ) -> Finding:
        return Finding(
            rule_id=SecretsRule.RULE_ID,
            severity=signature.severity,
            action=Action.REDACT,
            span=Span(start, end),
            message=f"Potential {signature.secret_type} detected.",
            redacted_preview=f"[REDACTED:{signature.secret_type}]",
            metadata={
                "secret_type": signature.secret_type,
                "provider": signature.provider,
                "signature_id": signature.signature_id,
                "signature_status": signature.status.value,
                "catalog_id": self._catalog.catalog_id,
                "catalog_version": self._catalog.version,
                "detector": "well_known_prefix",
                "span_basis": "characters",
            },
        )


__all__ = ["SecretStream", "SecretStreamState"]
