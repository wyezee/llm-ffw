"""Deterministic labeled accuracy corpus for opt-in PII rules."""

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import random

from llm_ffw import (
    EmailAddressConfig,
    EmailAddressRule,
    IPAddressConfig,
    IPAddressRule,
    ScanScope,
    Scanner,
)


_MANIFEST_PATH = Path(__file__).with_name("pii_accuracy_manifest.json")
_RULE_IDS = (EmailAddressRule.RULE_ID, IPAddressRule.RULE_ID)


@dataclass(frozen=True, slots=True)
class ExpectedPIIFinding:
    """Expected rule ownership and exact character span."""

    rule_id: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class PIIAccuracyScenario:
    """One synthetic labeled input without any real personal data."""

    scenario_id: str
    category: str
    text: str
    expected: tuple[ExpectedPIIFinding, ...]


@dataclass(frozen=True, slots=True)
class PIIAccuracyCorpus:
    """Reproducible in-memory scenarios and safe provenance metadata."""

    dataset_id: str
    seed: int
    uses_llm: bool
    uses_network: bool
    reserved_examples_only: bool
    scenarios: tuple[PIIAccuracyScenario, ...]

    @property
    def sha256(self) -> str:
        """Hash canonical scenario data for reproducibility."""

        serialized = json.dumps(
            [
                {
                    "scenario_id": scenario.scenario_id,
                    "category": scenario.category,
                    "text": scenario.text,
                    "expected": [
                        {
                            "rule_id": finding.rule_id,
                            "start": finding.start,
                            "end": finding.end,
                        }
                        for finding in scenario.expected
                    ],
                }
                for scenario in self.scenarios
            ],
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class RuleAccuracy:
    """Disclosure-safe confusion counts for one rule."""

    rule_id: str
    expected_findings: int
    true_positives: int
    false_positives: int
    false_negatives: int


@dataclass(frozen=True, slots=True)
class PIIAccuracyReport:
    """Aggregate evidence without retaining scenario text."""

    dataset_id: str
    corpus_sha256: str
    scenario_count: int
    expected_findings: int
    actual_findings: int
    true_positives: int
    true_negative_scenarios: int
    false_positives: int
    false_negatives: int
    redaction_failures: int
    rules: tuple[RuleAccuracy, ...]

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 1.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 1.0

    @property
    def exact_span_rate(self) -> float:
        return (
            self.true_positives / self.expected_findings
            if self.expected_findings
            else 1.0
        )


def _load_manifest(path: Path) -> dict[str, object]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("PII accuracy manifest must be an object")
    expected_keys = {
        "schema_version",
        "dataset_id",
        "seed",
        "uses_llm",
        "uses_network",
        "reserved_examples_only",
        "groups",
        "expected_sha256",
    }
    if set(manifest) != expected_keys:
        raise ValueError("PII accuracy manifest fields are invalid")
    if manifest["schema_version"] != 1:
        raise ValueError("unsupported PII accuracy manifest schema")
    if not isinstance(manifest["dataset_id"], str):
        raise TypeError("dataset_id must be a string")
    if isinstance(manifest["seed"], bool) or not isinstance(
        manifest["seed"], int
    ):
        raise TypeError("seed must be an integer")
    for field_name in (
        "uses_llm",
        "uses_network",
        "reserved_examples_only",
    ):
        if not isinstance(manifest[field_name], bool):
            raise TypeError(f"{field_name} must be a boolean")
    groups = manifest["groups"]
    expected_groups = {
        "email_positive",
        "ip_positive",
        "mixed_positive",
        "negative",
    }
    if not isinstance(groups, dict) or set(groups) != expected_groups:
        raise ValueError("PII accuracy groups are invalid")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in groups.values()
    ):
        raise ValueError("PII accuracy group counts must be positive integers")
    if not isinstance(manifest["expected_sha256"], str):
        raise TypeError("expected_sha256 must be a string")
    return manifest


def _finding(rule_id: str, text: str, value: str) -> ExpectedPIIFinding:
    start = text.index(value)
    return ExpectedPIIFinding(rule_id, start, start + len(value))


def _email_scenarios(count: int) -> list[PIIAccuracyScenario]:
    domains = (
        "example.com",
        "sub.example.org",
        "service.example.net",
        "mail.example.test",
        "mail.example.invalid",
    )
    contexts = (
        "Contact <{value}>.",
        "owner={value}",
        'record={{"email":"{value}"}}',
        "https://example.test/?owner={value}&source=synthetic",
    )
    scenarios: list[PIIAccuracyScenario] = []
    for index in range(count):
        local_parts = (
            f"user{index}",
            f"first.last{index}",
            f"team+tag{index}",
            f"account_{index}",
            f"percent%{index}",
        )
        local_part = local_parts[index % len(local_parts)]
        domain = domains[index % len(domains)]
        value = f"{local_part}@{domain}"
        text = contexts[index % len(contexts)].format(value=value)
        scenarios.append(
            PIIAccuracyScenario(
                scenario_id=f"email-positive-{index:04d}",
                category="email_positive",
                text=text,
                expected=(_finding(EmailAddressRule.RULE_ID, text, value),),
            )
        )
    return scenarios


def _ip_value(index: int) -> str:
    if index % 2 == 0:
        networks = ("192.0.2", "198.51.100", "203.0.113")
        return f"{networks[index % len(networks)]}.{index % 254 + 1}"
    return f"2001:db8:{index:x}::{index % 65_535 + 1:x}"


def _ip_scenarios(count: int) -> list[PIIAccuracyScenario]:
    contexts = (
        "source={value}",
        "endpoint=[{value}]",
        'record={{"address":"{value}"}}',
        "route from {value} to the synthetic service",
    )
    scenarios: list[PIIAccuracyScenario] = []
    for index in range(count):
        value = _ip_value(index)
        text = contexts[index % len(contexts)].format(value=value)
        scenarios.append(
            PIIAccuracyScenario(
                scenario_id=f"ip-positive-{index:04d}",
                category="ip_positive",
                text=text,
                expected=(_finding(IPAddressRule.RULE_ID, text, value),),
            )
        )
    return scenarios


def _mixed_scenarios(count: int) -> list[PIIAccuracyScenario]:
    scenarios: list[PIIAccuracyScenario] = []
    for index in range(count):
        email = f"mixed.user+{index}@example.com"
        address = _ip_value(index + 1_000)
        text = f"contact {email} from {address}"
        scenarios.append(
            PIIAccuracyScenario(
                scenario_id=f"mixed-positive-{index:04d}",
                category="mixed_positive",
                text=text,
                expected=(
                    _finding(EmailAddressRule.RULE_ID, text, email),
                    _finding(IPAddressRule.RULE_ID, text, address),
                ),
            )
        )
    return scenarios


def _negative_scenarios(count: int) -> list[PIIAccuracyScenario]:
    templates = (
        "release {a}.{b}.{c}.{d}-beta",
        "invalid address 999.{b}.{c}.{d}",
        "semantic version {a}.{b}.{c}",
        "clock value 12:34:56",
        "mailbox user{n}@example",
        "mailbox .user{n}@example.com",
        "mailbox user..{n}@example.com",
        "mailbox user{n}@example.1",
        "mailbox user{n}@exam_ple.com",
        "placeholder user{n}_at_example_dot_com",
        "invalid route 10.20.30.999",
        "short IPv6 form 2001:db8:{a}",
        "mailbox user{n}@-example.com",
        "mailbox user{n}@example.c",
        "commit 0123456789abcdef and tenant 550e8400-e29b-41d4-a716-446655440000",
        "documentation mentions email and IP address fields without values",
    )
    scenarios: list[PIIAccuracyScenario] = []
    for index in range(count):
        text = templates[index % len(templates)].format(
            n=index,
            a=index % 9 + 1,
            b=index % 17 + 1,
            c=index % 29 + 1,
            d=index % 251 + 1,
        )
        scenarios.append(
            PIIAccuracyScenario(
                scenario_id=f"negative-{index:04d}",
                category="negative",
                text=text,
                expected=(),
            )
        )
    return scenarios


def build_corpus(
    manifest_path: Path = _MANIFEST_PATH,
) -> PIIAccuracyCorpus:
    """Build and verify the committed deterministic corpus definition."""

    if not isinstance(manifest_path, Path):
        raise TypeError("manifest_path must be a pathlib.Path")
    manifest = _load_manifest(manifest_path)
    groups = manifest["groups"]
    if not isinstance(groups, dict):
        raise RuntimeError("validated groups changed type")
    scenarios = [
        *_email_scenarios(groups["email_positive"]),
        *_ip_scenarios(groups["ip_positive"]),
        *_mixed_scenarios(groups["mixed_positive"]),
        *_negative_scenarios(groups["negative"]),
    ]
    seed = manifest["seed"]
    if not isinstance(seed, int):
        raise RuntimeError("validated seed changed type")
    random.Random(seed).shuffle(scenarios)
    corpus = PIIAccuracyCorpus(
        dataset_id=str(manifest["dataset_id"]),
        seed=seed,
        uses_llm=bool(manifest["uses_llm"]),
        uses_network=bool(manifest["uses_network"]),
        reserved_examples_only=bool(manifest["reserved_examples_only"]),
        scenarios=tuple(scenarios),
    )
    expected_sha256 = manifest["expected_sha256"]
    if expected_sha256 != "PENDING" and corpus.sha256 != expected_sha256:
        raise RuntimeError("PII accuracy corpus digest does not match manifest")
    return corpus


def _expected_redaction(scenario: PIIAccuracyScenario) -> str:
    parts: list[str] = []
    cursor = 0
    for finding in sorted(scenario.expected, key=lambda item: item.start):
        if finding.start < cursor or finding.end > len(scenario.text):
            raise ValueError(
                f"invalid expected span in scenario {scenario.scenario_id}"
            )
        parts.extend((scenario.text[cursor : finding.start], "[REDACTED]"))
        cursor = finding.end
    parts.append(scenario.text[cursor:])
    return "".join(parts)


def evaluate_corpus(
    corpus: PIIAccuracyCorpus,
    *,
    scanner: Scanner | None = None,
) -> PIIAccuracyReport:
    """Evaluate exact rule, span, and redaction behavior."""

    if not isinstance(corpus, PIIAccuracyCorpus):
        raise TypeError("corpus must be a PIIAccuracyCorpus")
    if scanner is not None and not isinstance(scanner, Scanner):
        raise TypeError("scanner must be a Scanner or None")
    active_scanner = scanner or Scanner(
        rules=(EmailAddressRule(), IPAddressRule())
    )
    expected_by_rule: Counter[str] = Counter()
    actual_by_rule: Counter[str] = Counter()
    true_by_rule: Counter[str] = Counter()
    false_positive_by_rule: Counter[str] = Counter()
    false_negative_by_rule: Counter[str] = Counter()
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negative_scenarios = 0
    redaction_failures = 0
    actual_findings = 0
    expected_findings = 0
    for scenario in corpus.scenarios:
        findings = active_scanner.scan(
            scenario.text,
            scope=ScanScope.INPUT,
        )
        expected = {
            (item.rule_id, item.start, item.end) for item in scenario.expected
        }
        actual = {
            (item.rule_id, item.span.start, item.span.end) for item in findings
        }
        shared = expected & actual
        missing = expected - actual
        unexpected = actual - expected
        true_positives += len(shared)
        false_positives += len(unexpected)
        false_negatives += len(missing)
        expected_findings += len(expected)
        actual_findings += len(actual)
        expected_by_rule.update(item[0] for item in expected)
        actual_by_rule.update(item[0] for item in actual)
        true_by_rule.update(item[0] for item in shared)
        false_positive_by_rule.update(item[0] for item in unexpected)
        false_negative_by_rule.update(item[0] for item in missing)
        if not expected and not actual:
            true_negative_scenarios += 1
        if active_scanner.redact(scenario.text, findings) != _expected_redaction(
            scenario
        ):
            redaction_failures += 1
    discovered_rule_ids = set(expected_by_rule) | set(actual_by_rule)
    rules = tuple(
        RuleAccuracy(
            rule_id=rule_id,
            expected_findings=expected_by_rule[rule_id],
            true_positives=true_by_rule[rule_id],
            false_positives=false_positive_by_rule[rule_id],
            false_negatives=false_negative_by_rule[rule_id],
        )
        for rule_id in sorted(discovered_rule_ids)
    )
    return PIIAccuracyReport(
        dataset_id=corpus.dataset_id,
        corpus_sha256=corpus.sha256,
        scenario_count=len(corpus.scenarios),
        expected_findings=expected_findings,
        actual_findings=actual_findings,
        true_positives=true_positives,
        true_negative_scenarios=true_negative_scenarios,
        false_positives=false_positives,
        false_negatives=false_negatives,
        redaction_failures=redaction_failures,
        rules=rules,
    )


def write_corpus(
    corpus: PIIAccuracyCorpus,
    output_directory: Path,
) -> tuple[Path, Path]:
    """Write an optional generated JSONL corpus and disclosure-safe manifest."""

    if not isinstance(corpus, PIIAccuracyCorpus):
        raise TypeError("corpus must be a PIIAccuracyCorpus")
    if not isinstance(output_directory, Path):
        raise TypeError("output_directory must be a pathlib.Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    corpus_path = output_directory / "pii_accuracy_corpus.jsonl"
    manifest_path = output_directory / "pii_accuracy_generated_manifest.json"
    lines = [
        json.dumps(
            {
                "scenario_id": scenario.scenario_id,
                "category": scenario.category,
                "text": scenario.text,
                "expected": [
                    {
                        "rule_id": finding.rule_id,
                        "start": finding.start,
                        "end": finding.end,
                    }
                    for finding in scenario.expected
                ],
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        for scenario in corpus.scenarios
    ]
    corpus_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest_path.write_text(
        json.dumps(
            {
                "dataset_id": corpus.dataset_id,
                "seed": corpus.seed,
                "scenario_count": len(corpus.scenarios),
                "expected_finding_count": sum(
                    len(item.expected) for item in corpus.scenarios
                ),
                "sha256": corpus.sha256,
                "uses_llm": corpus.uses_llm,
                "uses_network": corpus.uses_network,
                "reserved_examples_only": corpus.reserved_examples_only,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return corpus_path, manifest_path


__all__ = [
    "ExpectedPIIFinding",
    "PIIAccuracyCorpus",
    "PIIAccuracyReport",
    "PIIAccuracyScenario",
    "RuleAccuracy",
    "build_corpus",
    "evaluate_corpus",
    "write_corpus",
]
