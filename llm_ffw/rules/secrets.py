"""Detection of credentials described by a constrained signature catalog."""

import re

from ..findings import Action, Severity, Span
from ..inspection import Inspection, ScanScope
from ..secret_catalog import BUILTIN_SECRET_CATALOG, SecretCatalog, SecretSignature
from .base import Rule, RuleMatch


class SecretsRule(Rule):
    """Find provider token shapes and apply signature-defined handling."""

    RULE_ID = "secrets.detected"
    PURPOSE = "Detect explicitly formatted credentials with well-known prefixes."
    SCOPES = frozenset((ScanScope.INPUT, ScanScope.OUTPUT))
    MAX_CANDIDATES = 128

    def __init__(self, catalog: SecretCatalog | None = None) -> None:
        if catalog is not None and not isinstance(catalog, SecretCatalog):
            raise TypeError("catalog must be a SecretCatalog or None")
        self._catalog = catalog if catalog is not None else BUILTIN_SECRET_CATALOG
        prefix_signatures: dict[str, SecretSignature] = {}
        for signature in self._catalog.signatures:
            for prefix in signature.prefixes:
                prefix_signatures[prefix] = signature
        prefixes = sorted(prefix_signatures, key=lambda item: (-len(item), item))
        # Catalog authors provide literals only. Escaping those literals creates a
        # bounded alternation with no user-controlled regex operators. Longest-first
        # ordering deterministically assigns nested formats such as sk-ant-*.
        alternatives = "|".join(re.escape(prefix) for prefix in prefixes)
        self._prefix_pattern = re.compile(f"({alternatives})", re.ASCII)
        self._prefix_signatures = prefix_signatures

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def purpose(self) -> str:
        return self.PURPOSE

    @property
    def scopes(self) -> frozenset[ScanScope]:
        return self.SCOPES

    @property
    def catalog(self) -> SecretCatalog:
        """Return the immutable catalog pinned to this rule instance."""

        return self._catalog

    def scan(self, inspection: Inspection) -> tuple[RuleMatch, ...]:
        if not isinstance(inspection, Inspection):
            raise TypeError("inspection must be an Inspection")
        text = inspection.text

        matches: list[RuleMatch] = []
        next_position = 0
        for prefix_match in self._prefix_pattern.finditer(text):
            position = prefix_match.start()
            if position < next_position:
                continue
            prefix = prefix_match.group(1)
            selected_signature = self._prefix_signatures[prefix]
            selected_prefix_end = position + len(prefix)
            if position > 0 and text[position - 1] in selected_signature.boundary_chars:
                continue

            match_end = selected_prefix_end
            suffix_length = 0
            while (
                match_end < len(text)
                and text[match_end] in selected_signature.suffix_chars
            ):
                match_end += 1
                suffix_length += 1
                maximum = selected_signature.max_suffix_chars
                if maximum is not None and suffix_length > maximum:
                    break

            maximum = selected_signature.max_suffix_chars
            valid_length = suffix_length >= selected_signature.min_suffix_chars and (
                maximum is None or suffix_length <= maximum
            )
            valid_boundary = (
                match_end == len(text)
                or text[match_end] not in selected_signature.boundary_chars
            )
            if not valid_length or not valid_boundary:
                continue
            if (
                selected_signature.suffix_ending
                and not text.endswith(
                    selected_signature.suffix_ending,
                    selected_prefix_end,
                    match_end,
                )
            ):
                continue

            if len(matches) >= self.MAX_CANDIDATES:
                matches.append(
                    RuleMatch(
                        span=Span(position, len(text)),
                        severity=Severity.HIGH,
                        action=Action.BLOCK,
                        message="Secret inspection limit exceeded.",
                        metadata={
                            "reason": "candidate_limit_exceeded",
                            "limit": str(self.MAX_CANDIDATES),
                            "catalog_id": self._catalog.catalog_id,
                            "catalog_version": self._catalog.version,
                            "detector": "well_known_prefix",
                            "span_basis": "characters",
                        },
                    )
                )
                break

            matches.append(
                RuleMatch(
                    span=Span(position, match_end),
                    severity=selected_signature.severity,
                    action=selected_signature.action,
                    message=f"Potential {selected_signature.secret_type} detected.",
                    redacted_preview=(
                        f"[REDACTED:{selected_signature.secret_type}]"
                        if selected_signature.action is Action.REDACT
                        else None
                    ),
                    metadata={
                        "secret_type": selected_signature.secret_type,
                        "provider": selected_signature.provider,
                        "signature_id": selected_signature.signature_id,
                        "signature_status": selected_signature.status.value,
                        "catalog_id": self._catalog.catalog_id,
                        "catalog_version": self._catalog.version,
                        "detector": "well_known_prefix",
                        "span_basis": "characters",
                    },
                )
            )
            next_position = match_end

        return tuple(matches)
