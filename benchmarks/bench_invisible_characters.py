"""Benchmark the clean fast path and remove-then-rescan slow path."""

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
    RuleEngine,
    ProcessScannerPool,
    ProcessScannerPoolConfig,
    RuleScanner,
    RuleScannerConfig,
)


_INVISIBLE_RUN = "\u200b\u200c\u200d\u2060\ufeff"


def _firewall(size: int, *, enabled: bool) -> RuleEngine:
    return RuleEngine(
        scanner=RuleScanner(
            config=RuleScannerConfig(
                max_input_chars=size,
                enable_invisible_characters=enabled,
            )
        )
    )


def _median_duration(callback: object, rounds: int) -> float:
    if not callable(callback):
        raise TypeError("callback must be callable")
    durations: list[float] = []
    for _ in range(rounds):
        started = time.perf_counter()
        callback()
        durations.append(time.perf_counter() - started)
    return median(durations)


def _paired_clean_durations(
    baseline: object,
    enabled: object,
    rounds: int,
) -> tuple[float, float]:
    if not callable(baseline) or not callable(enabled):
        raise TypeError("paired callbacks must be callable")
    baseline_durations: list[float] = []
    enabled_durations: list[float] = []
    for round_number in range(rounds):
        callbacks = (
            ((baseline, baseline_durations), (enabled, enabled_durations))
            if round_number % 2 == 0
            else ((enabled, enabled_durations), (baseline, baseline_durations))
        )
        for callback, durations in callbacks:
            started = time.perf_counter()
            callback()
            elapsed = time.perf_counter() - started
            durations.append(elapsed)
    return (
        median(baseline_durations),
        median(enabled_durations),
    )


def benchmark(
    *,
    size: int,
    rounds: int,
    workers: int,
    concurrency: int,
    process_requests: int,
) -> dict[str, float]:
    marker = "sk-" + _INVISIBLE_RUN + "A" * 20
    if size <= len(marker):
        raise ValueError("size must leave room for the benchmark marker")
    clean = "x" * size
    dirty = clean[: size - len(marker) - 1] + " " + marker
    baseline = _firewall(size, enabled=False)
    enabled = _firewall(size, enabled=True)

    def baseline_request() -> None:
        result = baseline.process(clean)
        if result.decision is not Action.ALLOW:
            raise RuntimeError("baseline clean request was not allowed")

    def enabled_request() -> None:
        result = enabled.process(clean)
        if result.decision is not Action.ALLOW:
            raise RuntimeError("enabled clean request was not allowed")

    def dirty_request() -> None:
        result = enabled.process(dirty)
        if (
            result.decision is not Action.REDACT
            or result.processed_text is None
            or any(character in result.processed_text for character in _INVISIBLE_RUN)
            or not result.processed_text.endswith("[REDACTED]")
        ):
            raise RuntimeError("dirty request was not removed and rescanned")

    baseline_request()
    enabled_request()
    baseline_seconds, enabled_seconds = _paired_clean_durations(
        baseline_request,
        enabled_request,
        rounds,
    )
    dirty_seconds = _median_duration(dirty_request, rounds)
    tracemalloc.start()
    dirty_request()
    _, dirty_peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    pool = ProcessScannerPool(
        scanner_config=RuleScannerConfig(
            max_input_chars=size,
            enable_invisible_characters=True,
        ),
        pool_config=ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=max(workers, concurrency),
        ),
    )
    with pool:
        dirty_result = pool.process(dirty, timeout=120)
        if dirty_result.decision is not Action.REDACT:
            raise RuntimeError("process warm-up did not redact the dirty request")
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as callers:
            results = tuple(
                callers.map(
                    lambda _: pool.process(dirty, timeout=120),
                    range(process_requests),
                )
            )
        process_seconds = time.perf_counter() - started
    if any(
        result.decision is not Action.REDACT
        or result.processed_text is None
        or any(character in result.processed_text for character in _INVISIBLE_RUN)
        for result in results
    ):
        raise RuntimeError("a concurrent process result was unsafe")

    mib = size / (1024 * 1024)
    return {
        "baseline_seconds": baseline_seconds,
        "enabled_clean_seconds": enabled_seconds,
        "clean_overhead_percent": (
            ((enabled_seconds / baseline_seconds) - 1) * 100
            if baseline_seconds
            else 0.0
        ),
        "dirty_seconds": dirty_seconds,
        "dirty_mib_per_second": mib / dirty_seconds,
        "dirty_peak_mib": dirty_peak_bytes / (1024 * 1024),
        "process_requests_per_second": process_requests / process_seconds,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=8_000_000)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--process-requests", type=int, default=8)
    parser.add_argument("--max-clean-overhead-percent", type=float)
    parser.add_argument("--min-dirty-throughput-mib-s", type=float)
    parser.add_argument("--max-dirty-peak-mib", type=float)
    parser.add_argument("--min-process-requests-per-second", type=float)
    args = parser.parse_args()
    if min(
        args.size,
        args.rounds,
        args.workers,
        args.concurrency,
        args.process_requests,
    ) <= 0:
        parser.error("benchmark counts and size must be positive")
    if args.concurrency < args.workers:
        parser.error("--concurrency must be at least --workers")

    result = benchmark(
        size=args.size,
        rounds=args.rounds,
        workers=args.workers,
        concurrency=args.concurrency,
        process_requests=args.process_requests,
    )
    for key, value in result.items():
        print(f"{key}={value:.6f}")
    if (
        args.max_clean_overhead_percent is not None
        and result["clean_overhead_percent"]
        > args.max_clean_overhead_percent
    ):
        raise SystemExit("clean invisible-rule overhead gate failed")
    if (
        args.min_dirty_throughput_mib_s is not None
        and result["dirty_mib_per_second"]
        < args.min_dirty_throughput_mib_s
    ):
        raise SystemExit("dirty invisible-rule throughput gate failed")
    if (
        args.max_dirty_peak_mib is not None
        and result["dirty_peak_mib"] > args.max_dirty_peak_mib
    ):
        raise SystemExit("dirty invisible-rule peak-memory gate failed")
    if (
        args.min_process_requests_per_second is not None
        and result["process_requests_per_second"]
        < args.min_process_requests_per_second
    ):
        raise SystemExit("process invisible-rule throughput gate failed")


if __name__ == "__main__":
    main()
