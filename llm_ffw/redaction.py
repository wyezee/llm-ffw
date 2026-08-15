"""Allocation-conscious redaction shared by scanner and policy paths."""

from collections.abc import Iterable

from .findings import Action, Finding, Span


def redact_findings(
    text: str,
    findings: Iterable[Finding],
    redaction_text: str,
) -> str:
    """Replace all effective REDACT spans with one linear string rebuild."""

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if not isinstance(redaction_text, str) or not redaction_text:
        raise ValueError("redaction_text must be a non-empty string")
    spans: list[Span] = []
    for finding in findings:
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

    parts: list[str] = []
    cursor = 0
    for span in merged:
        parts.append(text[cursor : span.start])
        parts.append(redaction_text)
        cursor = span.end
    parts.append(text[cursor:])
    return "".join(parts)


def sanitize_findings(
    text: str,
    findings: Iterable[Finding],
    redaction_text: str,
) -> str:
    """Apply REMOVE and REDACT spans in one bounded linear rebuild."""

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if not isinstance(redaction_text, str) or not redaction_text:
        raise ValueError("redaction_text must be a non-empty string")
    operations: list[tuple[Span, bool]] = []
    for finding in findings:
        if not isinstance(finding, Finding):
            raise TypeError("findings must contain Finding instances")
        if finding.span.end > len(text):
            raise ValueError("finding span is outside text")
        if finding.action is Action.REMOVE:
            operations.append((finding.span, False))
        elif finding.action is Action.REDACT:
            operations.append((finding.span, True))
    if not operations:
        return text

    merged: list[tuple[Span, bool]] = []
    for span, redact in sorted(operations, key=lambda item: item[0]):
        if merged and span.start <= merged[-1][0].end:
            previous, previous_redact = merged[-1]
            merged[-1] = (
                Span(previous.start, max(previous.end, span.end)),
                previous_redact or redact,
            )
        else:
            merged.append((span, redact))

    parts: list[str] = []
    cursor = 0
    for span, redact in merged:
        parts.append(text[cursor : span.start])
        if redact:
            parts.append(redaction_text)
        cursor = span.end
    parts.append(text[cursor:])
    return "".join(parts)


__all__ = ["redact_findings", "sanitize_findings"]
