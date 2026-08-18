"""Benchmark the production banned-substring rule at its catalog envelope."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from statistics import median
import sys
import time
import tracemalloc

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.bench_literal_matchers import build_patterns, build_workloads
from llm_ffw import (
    Action,
    BannedSubstring,
    BannedSubstringCatalog,
    BannedSubstringsRule,
    RuleEngine,
    ProcessScannerPool,
    ProcessScannerPoolConfig,
    RuleScanner,
    RuleScannerConfig,
)
from llm_ffw.rules.secrets import SecretsRule


def benchmark(
    *,
    size: int,
    rounds: int,
    workers: int,
    concurrency: int,
    process_requests: int,
) -> dict[str, float]:
    generated = build_patterns(1_024)
    catalog = BannedSubstringCatalog(
        "benchmark.banned_text",
        "1",
        tuple(BannedSubstring(item.pattern_id, item.value) for item in generated),
    )
    workloads = build_workloads(size, generated)
    clean = workloads["clean"][0]
    adversarial = workloads["prefix_dense"][0]
    matching = workloads["sparse_matches"][0]
    firewall = RuleEngine(
        scanner=RuleScanner(
            rules=(SecretsRule(), BannedSubstringsRule(catalog)),
            config=RuleScannerConfig(max_input_chars=size),
        )
    )

    def run(text: str, expected: Action) -> None:
        result = firewall.process(text)
        if result.decision is not expected:
            raise RuntimeError("unexpected direct benchmark decision")

    requests = (
        ("clean", clean, Action.ALLOW),
        ("adversarial", adversarial, Action.ALLOW),
        ("matching", matching, Action.REDACT),
    )
    durations: dict[str, list[float]] = {name: [] for name, _, _ in requests}
    for round_number in range(rounds):
        ordered = requests[round_number % len(requests) :] + requests[: round_number % len(requests)]
        for name, text, expected in ordered:
            started = time.perf_counter()
            run(text, expected)
            durations[name].append(time.perf_counter() - started)
    clean_seconds = median(durations["clean"])
    adversarial_seconds = median(durations["adversarial"])
    matching_seconds = median(durations["matching"])
    tracemalloc.start()
    run(matching, Action.REDACT)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    pool = ProcessScannerPool(
        scanner_config=RuleScannerConfig(max_input_chars=size),
        pool_config=ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=max(workers, concurrency),
        ),
        banned_substring_catalog=catalog,
    )
    with pool:
        if pool.process(matching, timeout=120).decision is not Action.REDACT:
            raise RuntimeError("process warm-up did not redact")
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as callers:
            results = tuple(
                callers.map(
                    lambda _: pool.process(matching, timeout=120),
                    range(process_requests),
                )
            )
        process_seconds = time.perf_counter() - started
    if any(item.decision is not Action.REDACT for item in results):
        raise RuntimeError("process benchmark returned an unsafe decision")

    mib = size / (1024 * 1024)
    return {
        "clean_mib_per_second": mib / clean_seconds,
        "adversarial_mib_per_second": mib / adversarial_seconds,
        "matching_mib_per_second": mib / matching_seconds,
        "matching_peak_mib": peak_bytes / (1024 * 1024),
        "process_requests_per_second": process_requests / process_seconds,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=8_000_000)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--process-requests", type=int, default=8)
    parser.add_argument("--min-throughput-mib-s", type=float, default=3.0)
    parser.add_argument("--max-peak-mib", type=float, default=128.0)
    parser.add_argument("--min-process-requests-per-second", type=float, default=0.5)
    args = parser.parse_args()
    result = benchmark(
        size=args.size,
        rounds=args.rounds,
        workers=args.workers,
        concurrency=args.concurrency,
        process_requests=args.process_requests,
    )
    for key, value in result.items():
        print(f"{key}={value:.6f}")
    if min(
        result["clean_mib_per_second"],
        result["adversarial_mib_per_second"],
        result["matching_mib_per_second"],
    ) < args.min_throughput_mib_s:
        raise SystemExit("banned-substring throughput gate failed")
    if result["matching_peak_mib"] > args.max_peak_mib:
        raise SystemExit("banned-substring memory gate failed")
    if (
        result["process_requests_per_second"]
        < args.min_process_requests_per_second
    ):
        raise SystemExit("banned-substring process gate failed")


if __name__ == "__main__":
    main()
