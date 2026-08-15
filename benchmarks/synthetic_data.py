"""Build deterministic, nonfunctional secret-scanner test corpora.

This module uses only local catalog metadata and the Python standard library.
It performs no network, LLM, randomness, or provider API calls.
"""

from dataclasses import dataclass
import hashlib

from llm_ffw import BUILTIN_SECRET_CATALOG, SecretCatalog, SecretSignature


@dataclass(frozen=True, slots=True)
class ExpectedFinding:
    """Expected catalog ownership and span for one synthetic token."""

    signature_id: str
    provider: str
    prefix: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class SyntheticDataset:
    """An exact-size corpus and independently constructed expectations."""

    text: str
    expected_findings: tuple[ExpectedFinding, ...]
    catalog_id: str
    catalog_version: str

    @property
    def sha256(self) -> str:
        """Return a stable digest without exposing corpus contents."""

        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()


def _suffix(signature: SecretSignature, length: int) -> str:
    if length < signature.min_suffix_chars:
        raise ValueError("synthetic suffix is shorter than the signature minimum")
    if signature.max_suffix_chars is not None and length > signature.max_suffix_chars:
        raise ValueError("synthetic suffix exceeds the signature maximum")

    fill = next(
        (character for character in "Aa0b1" if character in signature.suffix_chars),
        signature.suffix_chars[0],
    )
    ending = signature.suffix_ending
    return fill * (length - len(ending)) + ending


def synthetic_token(signature: SecretSignature, prefix: str) -> str:
    """Construct a stable, intentionally nonfunctional catalog-shaped value."""

    if prefix not in signature.prefixes:
        raise ValueError("prefix does not belong to the signature")
    return prefix + _suffix(signature, signature.min_suffix_chars)


def build_dataset(
    size: int = 8_000_000,
    *,
    catalog: SecretCatalog = BUILTIN_SECRET_CATALOG,
    matches_per_prefix: int = 1,
    include_near_misses: bool = True,
) -> SyntheticDataset:
    """Build an exact-character-size dataset with every catalog prefix represented."""

    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise ValueError("size must be a positive integer")
    if (
        isinstance(matches_per_prefix, bool)
        or not isinstance(matches_per_prefix, int)
        or matches_per_prefix <= 0
    ):
        raise ValueError("matches_per_prefix must be a positive integer")
    if not isinstance(catalog, SecretCatalog):
        raise TypeError("catalog must be a SecretCatalog")

    parts: list[str] = []
    expected: list[ExpectedFinding] = []
    cursor = 0
    case_number = 0
    for signature in catalog.signatures:
        for prefix in signature.prefixes:
            for _ in range(matches_per_prefix):
                label = f"synthetic_case_{case_number:04d}= "
                token = synthetic_token(signature, prefix)
                parts.append(label)
                cursor += len(label)
                start = cursor
                parts.append(token)
                cursor += len(token)
                expected.append(
                    ExpectedFinding(
                        signature_id=signature.signature_id,
                        provider=signature.provider,
                        prefix=prefix,
                        start=start,
                        end=cursor,
                    )
                )
                parts.append("\n")
                cursor += 1
                case_number += 1

            if include_near_misses:
                label = f"short_nonmatch_{case_number:04d}= "
                short_length = signature.min_suffix_chars - 1
                parts.extend((label, prefix, _suffix(signature, short_length + 1)[:-1], "\n"))
                cursor += len(label) + len(prefix) + short_length + 1
                case_number += 1

    if cursor > size:
        raise ValueError(
            f"size {size} is too small; catalog cases require at least {cursor} characters"
        )
    parts.append("safe_padding_line\n" * ((size - cursor) // 18))
    cursor = sum(map(len, parts))
    parts.append("z" * (size - cursor))
    text = "".join(parts)
    if len(text) != size:  # Defensive invariant for benchmark comparability.
        raise RuntimeError("synthetic dataset length invariant failed")

    return SyntheticDataset(
        text=text,
        expected_findings=tuple(expected),
        catalog_id=catalog.catalog_id,
        catalog_version=catalog.version,
    )


__all__ = [
    "ExpectedFinding",
    "SyntheticDataset",
    "build_dataset",
    "synthetic_token",
]
