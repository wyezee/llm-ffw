"""Enforce deterministic PII accuracy and exact-redaction thresholds."""

import argparse
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.pii_accuracy import (
    PIIAccuracyReport,
    build_corpus,
    evaluate_corpus,
)


_EXPECTED_CATEGORIES = {
    "curated_email_positive",
    "curated_ip_positive",
    "curated_mac_positive",
    "curated_mac_negative",
    "curated_negative",
    "email_positive",
    "ip_positive",
    "mac_positive",
    "mixed_positive",
    "negative",
}


def _rate(value: object, name: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 <= value <= 1
    ):
        raise ValueError(f"{name} must be a finite number from 0 to 1")
    return float(value)


def run_gate(
    *,
    min_precision: float = 1.0,
    min_recall: float = 1.0,
    min_exact_span_rate: float = 1.0,
    max_redaction_failures: int = 0,
) -> PIIAccuracyReport:
    """Build, evaluate, and enforce the committed PII corpus."""

    precision_threshold = _rate(min_precision, "min_precision")
    recall_threshold = _rate(min_recall, "min_recall")
    span_threshold = _rate(min_exact_span_rate, "min_exact_span_rate")
    if (
        isinstance(max_redaction_failures, bool)
        or not isinstance(max_redaction_failures, int)
        or max_redaction_failures < 0
    ):
        raise ValueError("max_redaction_failures must be a non-negative integer")
    corpus = build_corpus()
    if corpus.uses_llm or corpus.uses_network:
        raise AssertionError("PII corpus provenance gate failed")
    if not corpus.synthetic_examples_only:
        raise AssertionError("PII corpus must use synthetic examples only")
    report = evaluate_corpus(corpus)
    if set(item.rule_id for item in report.rules) != {
        "pii.email_address",
        "pii.ip_address",
        "pii.mac_address",
    }:
        raise AssertionError("PII accuracy gate rule coverage is incomplete")
    if any(item.expected_findings <= 0 for item in report.rules):
        raise AssertionError("PII accuracy gate has an untested rule")
    if {item.category for item in report.categories} != _EXPECTED_CATEGORIES:
        raise AssertionError("PII accuracy gate category coverage is incomplete")
    if any(item.scenario_count <= 0 for item in report.categories):
        raise AssertionError("PII accuracy gate has an empty category")
    if report.precision < precision_threshold:
        raise AssertionError("PII accuracy precision threshold failed")
    if report.recall < recall_threshold:
        raise AssertionError("PII accuracy recall threshold failed")
    if report.exact_span_rate < span_threshold:
        raise AssertionError("PII exact-span threshold failed")
    if report.redaction_failures > max_redaction_failures:
        raise AssertionError("PII redaction threshold failed")
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min-precision", type=float, default=1.0)
    parser.add_argument("--min-recall", type=float, default=1.0)
    parser.add_argument("--min-exact-span-rate", type=float, default=1.0)
    parser.add_argument("--max-redaction-failures", type=int, default=0)
    return parser


def main() -> None:
    args = _parser().parse_args()
    report = run_gate(
        min_precision=args.min_precision,
        min_recall=args.min_recall,
        min_exact_span_rate=args.min_exact_span_rate,
        max_redaction_failures=args.max_redaction_failures,
    )
    print(f"dataset_id={report.dataset_id}")
    print(f"corpus_sha256={report.corpus_sha256}")
    print(f"scenarios={report.scenario_count}")
    print(f"expected_findings={report.expected_findings}")
    print(f"actual_findings={report.actual_findings}")
    print(f"true_positives={report.true_positives}")
    print(f"true_negative_scenarios={report.true_negative_scenarios}")
    print(f"false_positives={report.false_positives}")
    print(f"false_negatives={report.false_negatives}")
    print(f"precision={report.precision:.6f}")
    print(f"recall={report.recall:.6f}")
    print(f"exact_span_rate={report.exact_span_rate:.6f}")
    print(f"redaction_failures={report.redaction_failures}")
    for rule in report.rules:
        prefix = rule.rule_id.replace(".", "_")
        print(f"{prefix}_expected={rule.expected_findings}")
        print(f"{prefix}_true_positives={rule.true_positives}")
        print(f"{prefix}_false_positives={rule.false_positives}")
        print(f"{prefix}_false_negatives={rule.false_negatives}")
    for category in report.categories:
        prefix = f"category_{category.category}"
        print(f"{prefix}_scenarios={category.scenario_count}")
        print(f"{prefix}_false_positives={category.false_positives}")
        print(f"{prefix}_false_negatives={category.false_negatives}")
        print(f"{prefix}_redaction_failures={category.redaction_failures}")
    print("uses_llm=false")
    print("uses_network=false")
    print("pii_accuracy_gate=passed")


if __name__ == "__main__":
    main()
