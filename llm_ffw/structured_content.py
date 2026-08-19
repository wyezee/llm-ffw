"""Shared deterministic inspection for string leaves in structured JSON."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .findings import Action
from .inspection import ScanScope

if TYPE_CHECKING:
    from .engine import RuleScanner


@dataclass(frozen=True, slots=True)
class StructuredContentViolation:
    """Disclosure-safe identity of the first structured content violation."""

    rule_id: str
    action: Action


def first_structured_content_violation(
    roots: tuple[object, ...],
    *,
    scanner: "RuleScanner",
    scope: ScanScope,
) -> StructuredContentViolation | None:
    """Scan JSON keys and string values without retaining matched content."""

    stack = list(reversed(roots))
    while stack:
        value = stack.pop()
        if type(value) is str:
            findings = scanner.scan(value, scope=scope)
            if findings:
                first = findings[0]
                return StructuredContentViolation(
                    rule_id=first.rule_id,
                    action=first.action,
                )
        elif isinstance(value, Mapping):
            items = tuple(value.items())
            for key, child in reversed(items):
                stack.append(child)
                stack.append(key)
        elif isinstance(value, tuple):
            stack.extend(reversed(value))
    return None


__all__ = [
    "StructuredContentViolation",
    "first_structured_content_violation",
]
