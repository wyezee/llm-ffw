"""Internal incremental redaction with optional secret detection."""

from dataclasses import dataclass
from enum import Enum
import re

from .findings import Action, Finding, Severity, Span
from .rules.secrets import SecretsRule
from .secret_catalog import (
    SecretCatalog,
    SecretSignature,
)


class _EngineState(str, Enum):
    """Internal lifecycle state for incremental redaction."""

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


class _IncrementalRedactionEngine:
    """Fuse secret detection with externally finalized redaction findings."""

    MAX_PENDING_CANDIDATE_CHARS = 65_536

    __slots__ = (
        "_active_unbounded",
        "_catalog",
        "_external_findings",
        "_external_pending",
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
        "_redaction_at_boundary",
        "_received_chars",
        "_redaction_text",
        "_signatures_by_prefix",
        "_state",
    )

    def __init__(
        self,
        *,
        catalog: SecretCatalog | None,
        max_input_chars: int = 8_000_000,
        redaction_text: str = "[REDACTED]",
    ) -> None:
        if catalog is not None and not isinstance(catalog, SecretCatalog):
            raise TypeError("catalog must be a SecretCatalog or None")
        signatures = catalog.signatures if catalog is not None else ()
        for signature in signatures:
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
                    for signature in signatures
                    for prefix in signature.prefixes
                ),
                key=lambda item: (-len(item[0]), item[0]),
            )
        )
        alternatives = "|".join(re.escape(prefix) for prefix, _ in entries)
        self._prefix_pattern = (
            re.compile(f"({alternatives})", re.ASCII)
            if alternatives
            else None
        )
        self._signatures_by_prefix = dict(entries)
        partial_owners: dict[str, list[SecretSignature]] = {}
        for prefix, signature in entries:
            for length in range(1, len(prefix)):
                partial_owners.setdefault(prefix[:length], []).append(signature)
        self._partial_owners = {
            fragment: tuple(owners)
            for fragment, owners in partial_owners.items()
        }
        self._max_prefix_chars = max(
            (len(prefix) for prefix, _ in entries),
            default=0,
        )

        self._catalog = catalog
        self._max_input_chars = max_input_chars
        self._redaction_text = redaction_text
        self._pending = ""
        self._pending_offset = 0
        self._previous_char = ""
        self._redaction_at_boundary = False
        self._active_unbounded: _UnboundedCandidate | None = None
        self._overflow_start: int | None = None
        self._overflow_finding_added = False
        self._received_chars = 0
        self._max_buffered_chars = 0
        self._findings: list[Finding] = []
        self._external_findings: list[Finding] = []
        self._external_pending: list[Finding] = []
        self._state = _EngineState.OPEN

    @property
    def state(self) -> _EngineState:
        """Return the current stream lifecycle state."""

        return self._state

    @property
    def catalog(self) -> SecretCatalog | None:
        """Return the immutable secret catalog, when enabled."""

        return self._catalog

    @property
    def findings(self) -> tuple[Finding, ...]:
        """Return completed disclosure-safe findings in source order."""

        return tuple(
            sorted(
                (*self._findings, *self._external_findings),
                key=lambda finding: (
                    finding.span.start,
                    finding.span.end,
                    finding.rule_id,
                    tuple(sorted(finding.metadata.items())),
                ),
            )
        )

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

    def feed(
        self,
        chunk: str,
        *,
        external_findings: tuple[Finding, ...] = (),
    ) -> str:
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
        try:
            selected_external = tuple(external_findings)
        except TypeError as exc:
            raise TypeError("external_findings must be iterable") from exc
        for finding in selected_external:
            if not isinstance(finding, Finding):
                raise TypeError("external_findings must contain Finding values")
            if finding.action is not Action.REDACT:
                raise ValueError("external findings must have REDACT action")
            if finding.span.end > new_total:
                raise ValueError("external finding extends beyond received text")
        self._external_findings.extend(selected_external)
        self._external_pending.extend(selected_external)
        self._external_pending.sort(key=lambda finding: finding.span)
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
                self._drop_external_covered_through(self._received_chars)
                self._complete_unbounded(self._received_chars)
            elif self._pending:
                plan = self._plan_segment(self._pending, final=True)
                parts.append(self._apply_plan(self._pending, plan))
                self._pending = ""
            self._state = _EngineState.FINISHED
            return "".join(parts)
        except BaseException:
            self.cancel()
            raise

    def cancel(self) -> None:
        """Cancel an open stream and release retained source text."""

        if self._state is _EngineState.OPEN:
            self._pending = ""
            self._previous_char = ""
            self._redaction_at_boundary = False
            self._active_unbounded = None
            self._external_pending.clear()
            self._state = _EngineState.CANCELLED

    def _require_open(self) -> None:
        if self._state is not _EngineState.OPEN:
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
        plan = self._constrain_plan(plan)
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
            self._drop_external_covered_through(active.end)
            return ""
        covered_until = self._consume_external_overlap(active.end)
        self._complete_unbounded(active.end)
        covered_chars = covered_until - active.end
        if covered_chars:
            self._previous_char = chunk[end + covered_chars - 1]
        else:
            self._previous_char = active.last_char
        remainder_start = end + covered_chars
        if remainder_start == len(chunk):
            return ""
        return self._consume(
            chunk[remainder_start:],
            chunk_start=chunk_start + remainder_start,
        )

    def _complete_unbounded(self, end: int) -> None:
        active = self._active_unbounded
        if active is None:
            raise RuntimeError("unbounded candidate state is missing")
        self._findings.append(
            self._secret_finding(active.signature, active.start, end)
        )
        self._active_unbounded = None

    def _drop_external_covered_through(self, end: int) -> None:
        self._external_pending = [
            finding
            for finding in self._external_pending
            if finding.span.end > end
        ]

    def _consume_external_overlap(self, covered_until: int) -> int:
        remaining: list[Finding] = []
        for finding in self._external_pending:
            if finding.span.start <= covered_until:
                covered_until = max(covered_until, finding.span.end)
            else:
                remaining.append(finding)
        self._external_pending = remaining
        return covered_until

    def _plan_segment(self, text: str, *, final: bool) -> _SegmentPlan:
        matches: list[_PlannedMatch] = []
        next_position = 0
        prefix_matches = (
            self._prefix_pattern.finditer(text)
            if self._prefix_pattern is not None
            else ()
        )
        for prefix_match in prefix_matches:
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
        if self._max_prefix_chars == 0:
            return None
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

    def _constrain_plan(self, plan: _SegmentPlan) -> _SegmentPlan:
        absolute_safe = self._pending_offset + plan.safe_end
        constrained_safe = plan.safe_end
        for finding in self._external_pending:
            if finding.span.start < absolute_safe < finding.span.end:
                constrained_safe = min(
                    constrained_safe,
                    max(0, finding.span.start - self._pending_offset),
                )
        if constrained_safe == plan.safe_end:
            return plan
        return _SegmentPlan(
            safe_end=constrained_safe,
            matches=tuple(
                match
                for match in plan.matches
                if match.end <= constrained_safe
            ),
        )

    def _apply_plan(self, text: str, plan: _SegmentPlan) -> str:
        absolute_safe = self._pending_offset + plan.safe_end
        redactions = [Span(match.start, match.end) for match in plan.matches]
        for match in plan.matches:
            self._findings.append(match.finding)
        remaining_external: list[Finding] = []
        for finding in self._external_pending:
            if finding.span.end <= absolute_safe:
                redactions.append(
                    Span(
                        finding.span.start - self._pending_offset,
                        finding.span.end - self._pending_offset,
                    )
                )
            else:
                remaining_external.append(finding)
        self._external_pending = remaining_external

        merged: list[Span] = []
        for span in sorted(redactions):
            if merged and span.start <= merged[-1].end:
                previous = merged[-1]
                merged[-1] = Span(previous.start, max(previous.end, span.end))
            else:
                merged.append(span)
        parts: list[str] = []
        cursor = 0
        suppress_first_marker = bool(
            self._redaction_at_boundary
            and merged
            and merged[0].start == 0
        )
        for index, span in enumerate(merged):
            parts.append(text[cursor : span.start])
            if not (index == 0 and suppress_first_marker):
                parts.append(self._redaction_text)
            cursor = span.end
        parts.append(text[cursor : plan.safe_end])
        emission = "".join(parts)
        redaction_reaches_safe_end = bool(
            merged and merged[-1].end == plan.safe_end
        )
        redaction_continues = bool(
            redaction_reaches_safe_end
            or (self._redaction_at_boundary and plan.safe_end == 0)
        )

        if plan.safe_end:
            self._previous_char = text[plan.safe_end - 1]
        self._pending = text[plan.safe_end:]
        self._pending_offset += plan.safe_end

        if plan.overflow_start is not None:
            self._overflow_start = plan.overflow_start
            self._pending = ""
            if not redaction_continues:
                emission += self._redaction_text
            self._redaction_at_boundary = True
        elif plan.unbounded is not None:
            if len(self._findings) >= SecretsRule.MAX_CANDIDATES:
                self._overflow_start = plan.unbounded.start
            else:
                self._active_unbounded = plan.unbounded
            self._pending = ""
            if not redaction_continues:
                emission += self._redaction_text
            self._redaction_at_boundary = True
        elif plan.safe_end:
            self._redaction_at_boundary = redaction_reaches_safe_end
        return emission

    def _add_overflow_finding(self) -> None:
        if self._overflow_finding_added:
            return
        start = self._overflow_start
        if start is None:
            raise RuntimeError("overflow state is missing")
        if self._catalog is None:
            raise RuntimeError("secret catalog is missing")
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
        catalog = self._catalog
        if catalog is None:
            raise RuntimeError("secret catalog is missing")
        return Finding(
            rule_id=SecretsRule.RULE_ID,
            severity=signature.severity,
            action=Action.REDACT,
            span=Span(start, end),
            message=f"Potential {signature.secret_type} detected.",
            redacted_preview=(
                f"[REDACTED:{signature.secret_type}]"
                if signature.action is Action.REDACT
                else None
            ),
            metadata={
                "secret_type": signature.secret_type,
                "provider": signature.provider,
                "signature_id": signature.signature_id,
                "signature_status": signature.status.value,
                "catalog_id": catalog.catalog_id,
                "catalog_version": catalog.version,
                "detector": "well_known_prefix",
                "span_basis": "characters",
            },
        )


__all__: list[str] = []
