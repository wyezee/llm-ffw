"""Benchmark opt-in excessive-repetition inspection at the payload envelope."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from statistics import median
import sys
import time
import tracemalloc

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm_ffw import (
    Action,
    ProcessScannerPool,
    ProcessScannerPoolConfig,
    RepetitionConfig,
    RepetitionRule,
    RuleScanner,
    RuleScannerConfig,
    ScanScope,
)


def benchmark(
    *,
    size: int,
    rounds: int,
    workers: int,
    concurrency: int,
    process_requests: int,
) -> dict[str, float]:
    scanner = RuleScanner(rules=(RepetitionRule(),))
    workloads = {
        "clean": ("ab" * ((size + 1) // 2))[:size],
        "separator_dense": ("- " * ((size + 1) // 2))[:size],
        "word_dense": ("alpha beta " * ((size // 11) + 1))[:size],
        "line_dense": ("alpha beta\ngamma delta\n" * ((size // 23) + 1))[:size],
        "near_character_run": (
            (("a" * 255) + "b") * ((size // 256) + 1)
        )[:size],
        "character_run": "x" * size,
    }
    durations = {name: [] for name in workloads}
    for _ in range(rounds):
        for name, text in workloads.items():
            started = time.perf_counter()
            findings = scanner.scan(text, scope=ScanScope.INPUT)
            durations[name].append(time.perf_counter() - started)
            if (name == "character_run") != bool(findings):
                raise RuntimeError("unexpected repetition benchmark result")

    tracemalloc.start()
    for text in workloads.values():
        scanner.scan(text, scope=ScanScope.INPUT)
    scanner.scan(("aa " * ((size // 3) + 1))[:size], scope=ScanScope.INPUT)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    pool = ProcessScannerPool(
        scanner_config=RuleScannerConfig(max_input_chars=size),
        pool_config=ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=max(workers, concurrency),
        ),
        repetition_config=RepetitionConfig(),
    )
    with pool:
        warmup = pool.process(
            workloads["character_run"], scope=ScanScope.INPUT, timeout=120
        )
        if warmup.decision is not Action.REVIEW:
            raise RuntimeError("process warm-up missed excessive repetition")
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as callers:
            results = tuple(
                callers.map(
                    lambda _: pool.process(
                        workloads["character_run"],
                        scope=ScanScope.INPUT,
                        timeout=120,
                    ),
                    range(process_requests),
                )
            )
        process_seconds = time.perf_counter() - started
    if any(item.decision is not Action.REVIEW for item in results):
        raise RuntimeError("process benchmark missed excessive repetition")
    mib = size / (1024 * 1024)
    return {
        **{
            f"{name}_mib_per_second": mib / median(values)
            for name, values in durations.items()
        },
        "peak_mib": peak_bytes / (1024 * 1024),
        "process_requests_per_second": process_requests / process_seconds,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=8_000_000)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--process-requests", type=int, default=8)
    parser.add_argument("--min-throughput-mib-s", type=float, default=2.0)
    parser.add_argument("--max-peak-mib", type=float, default=128.0)
    parser.add_argument(
        "--min-process-requests-per-second", type=float, default=0.5
    )
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
        result["separator_dense_mib_per_second"],
        result["word_dense_mib_per_second"],
        result["line_dense_mib_per_second"],
        result["near_character_run_mib_per_second"],
        result["character_run_mib_per_second"],
    ) < args.min_throughput_mib_s:
        raise SystemExit("repetition throughput gate failed")
    if result["peak_mib"] > args.max_peak_mib:
        raise SystemExit("repetition memory gate failed")
    if (
        result["process_requests_per_second"]
        < args.min_process_requests_per_second
    ):
        raise SystemExit("repetition process gate failed")


if __name__ == "__main__":
    main()
