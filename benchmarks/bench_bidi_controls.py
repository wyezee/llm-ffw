"""Benchmark bounded Unicode bidirectional-control inspection."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import statistics
import sys
import time
import tracemalloc

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm_ffw import (
    Action,
    BidiControlRule,
    ProcessScannerPool,
    ProcessScannerPoolConfig,
    RuleEngine,
    RuleScanner,
    ScanScope,
)


def _exact(unit: str, size: int, *, suffix: str = "") -> str:
    if len(suffix) > size:
        raise ValueError("suffix exceeds requested size")
    body_size = size - len(suffix)
    return (unit * ((body_size // len(unit)) + 1))[:body_size] + suffix


def benchmark(
    *,
    size: int,
    rounds: int,
    workers: int,
    concurrency: int,
    process_requests: int,
) -> dict[str, float]:
    if min(size, rounds, workers, concurrency, process_requests) <= 0:
        raise ValueError("benchmark arguments must be positive")
    engine = RuleEngine(scanner=RuleScanner(rules=(BidiControlRule(),)))
    workloads = (
        ("ascii_clean", "x" * size, Action.ALLOW),
        (
            "multilingual_clean",
            _exact("العربية עברית text 123 ", size),
            Action.ALLOW,
        ),
        (
            "override_at_end",
            _exact("x", size, suffix="logical\u202evisual"),
            Action.REMOVE,
        ),
        (
            "isolate_at_end",
            _exact("x", size, suffix="left\u2068right\u2069"),
            Action.REVIEW,
        ),
        (
            "override_dense",
            _exact("x\u202e", size),
            Action.BLOCK,
        ),
    )
    durations: dict[str, list[float]] = {
        name: [] for name, _, _ in workloads
    }
    for round_number in range(rounds):
        ordered = (
            workloads[round_number % len(workloads) :]
            + workloads[: round_number % len(workloads)]
        )
        for name, text, expected in ordered:
            started = time.perf_counter()
            result = engine.process(text, scope=ScanScope.INPUT)
            durations[name].append(time.perf_counter() - started)
            if result.decision is not expected:
                raise RuntimeError(
                    f"unexpected bidi-control decision for {name}: "
                    f"{result.decision.value}"
                )

    override_text = workloads[2][1]
    tracemalloc.start()
    measured = engine.process(override_text, scope=ScanScope.INPUT)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if measured.decision is not Action.REMOVE:
        raise RuntimeError("bidi-control memory workload was not sanitized")

    pool = ProcessScannerPool(
        pool_config=ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=max(workers, concurrency),
        )
    )
    with pool:
        if (
            pool.process(
                override_text,
                scope=ScanScope.OUTPUT,
                timeout=120,
            ).decision
            is not Action.REMOVE
        ):
            raise RuntimeError("process warm-up did not remove bidi override")
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as callers:
            results = tuple(
                callers.map(
                    lambda _: pool.process(
                        override_text,
                        scope=ScanScope.OUTPUT,
                        timeout=120,
                    ),
                    range(process_requests),
                )
            )
        process_seconds = time.perf_counter() - started
    if any(item.decision is not Action.REMOVE for item in results):
        raise RuntimeError("process benchmark did not remove bidi override")

    mib = size / (1024 * 1024)
    return {
        **{
            f"{name}_mib_per_second": mib / statistics.median(values)
            for name, values in durations.items()
        },
        "override_peak_mib": peak_bytes / (1024 * 1024),
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
    throughput = tuple(
        value for key, value in result.items() if key.endswith("_mib_per_second")
    )
    if min(throughput) < args.min_throughput_mib_s:
        raise SystemExit("bidi-control throughput gate failed")
    if result["override_peak_mib"] > args.max_peak_mib:
        raise SystemExit("bidi-control memory gate failed")
    if (
        result["process_requests_per_second"]
        < args.min_process_requests_per_second
    ):
        raise SystemExit("bidi-control process gate failed")


if __name__ == "__main__":
    main()
