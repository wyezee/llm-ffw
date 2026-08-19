"""Benchmark bounded external image-resource inspection."""

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
    ExternalResourceConfig,
    ExternalResourceRule,
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
    config = ExternalResourceConfig(
        allowed_hostname_suffixes=("assets.example",)
    )
    engine = RuleEngine(
        scanner=RuleScanner(rules=(ExternalResourceRule(config),))
    )
    external = "![x](https://outside.example/pixel.png)"
    hostname_encoded = (
        '<img src="https://736563726574.attacker.example/a.png">'
    )
    allowed = "![x](https://cdn.assets.example/pixel.png?cache=one)"
    workloads = (
        ("ascii_clean", "x" * size, Action.ALLOW),
        (
            "markup_clean",
            _exact("ordinary markdown output line\n", size),
            Action.ALLOW,
        ),
        (
            "invalid_marker_dense",
            _exact("![label] ordinary text\n", size),
            Action.ALLOW,
        ),
        ("external_at_end", _exact("x", size, suffix=external), Action.REDACT),
        (
            "hostname_encoded_at_end",
            _exact("x", size, suffix=hostname_encoded),
            Action.REDACT,
        ),
        ("allowed_at_end", _exact("x", size, suffix=allowed), Action.ALLOW),
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
            result = engine.process(text, scope=ScanScope.OUTPUT)
            durations[name].append(time.perf_counter() - started)
            if result.decision is not expected:
                raise RuntimeError(
                    f"unexpected external-resource decision for {name}: "
                    f"{result.decision.value}"
                )

    external_text = next(
        text for name, text, _ in workloads if name == "external_at_end"
    )
    tracemalloc.start()
    measured = engine.process(external_text, scope=ScanScope.OUTPUT)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if measured.decision is not Action.REDACT:
        raise RuntimeError("external-resource memory workload was not redacted")

    pool = ProcessScannerPool(
        external_resource_config=config,
        pool_config=ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=max(workers, concurrency),
        ),
    )
    with pool:
        if (
            pool.process(
                external_text,
                scope=ScanScope.OUTPUT,
                timeout=120,
            ).decision
            is not Action.REDACT
        ):
            raise RuntimeError("process warm-up did not redact external resource")
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as callers:
            results = tuple(
                callers.map(
                    lambda _: pool.process(
                        external_text,
                        scope=ScanScope.OUTPUT,
                        timeout=120,
                    ),
                    range(process_requests),
                )
            )
        process_seconds = time.perf_counter() - started
    if any(item.decision is not Action.REDACT for item in results):
        raise RuntimeError("process benchmark did not redact external resource")

    mib = size / (1024 * 1024)
    return {
        **{
            f"{name}_mib_per_second": mib / statistics.median(values)
            for name, values in durations.items()
        },
        "external_peak_mib": peak_bytes / (1024 * 1024),
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
    for name, value in result.items():
        print(f"{name}={value:.6f}")
    throughput = tuple(
        value for name, value in result.items() if name.endswith("mib_per_second")
    )
    if min(throughput) < args.min_throughput_mib_s:
        raise SystemExit("external-resource throughput gate failed")
    if result["external_peak_mib"] > args.max_peak_mib:
        raise SystemExit("external-resource memory gate failed")
    if (
        result["process_requests_per_second"]
        < args.min_process_requests_per_second
    ):
        raise SystemExit("external-resource process throughput gate failed")


if __name__ == "__main__":
    main()
