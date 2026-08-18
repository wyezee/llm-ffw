"""Benchmark unsafe-URL inspection at the production payload envelope."""

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
    ScanScope,
    UnsafeURLConfig,
    UnsafeURLRule,
)
from llm_ffw.rules.secrets import SecretsRule


def _sized_suffix(size: int, suffix: str, fill: str = "a") -> str:
    if len(suffix) > size:
        raise ValueError("size is too small for benchmark suffix")
    repeats, remainder = divmod(size - len(suffix), len(fill))
    return (fill * repeats) + fill[:remainder] + suffix


def benchmark(
    *,
    size: int,
    rounds: int,
    workers: int,
    concurrency: int,
    process_requests: int,
) -> dict[str, float]:
    url_config = UnsafeURLConfig()
    scanner_config = RuleScannerConfig(max_input_chars=size)
    firewall = RuleEngine(
        scanner=RuleScanner(
            rules=(SecretsRule(), UnsafeURLRule(url_config)),
            config=scanner_config,
        )
    )
    workloads = (
        ("clean", "a" * size, Action.ALLOW),
        ("near_miss", _sized_suffix(size, "", "http:/"), Action.ALLOW),
        (
            "safe_at_end",
            _sized_suffix(size, " https://example.com/path"),
            Action.ALLOW,
        ),
        (
            "unsafe_at_end",
            _sized_suffix(size, " javascript:alert(1)"),
            Action.REDACT,
        ),
        (
            "metadata_host_at_end",
            _sized_suffix(
                size,
                " http://metadata.google.internal/computeMetadata/v1/",
            ),
            Action.REDACT,
        ),
        (
            "overlapping_schemes",
            _sized_suffix(size, "", "http://"),
            Action.REDACT,
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
            result = firewall.process(text, scope=ScanScope.OUTPUT)
            durations[name].append(time.perf_counter() - started)
            if result.decision is not expected:
                raise RuntimeError("unexpected URL benchmark decision")

    unsafe = workloads[-1][1]
    tracemalloc.start()
    measured = firewall.process(unsafe, scope=ScanScope.OUTPUT)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if measured.decision is not Action.REDACT:
        raise RuntimeError("unsafe URL memory workload was not sanitized")

    pool = ProcessScannerPool(
        scanner_config=scanner_config,
        pool_config=ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=max(workers, concurrency),
        ),
        unsafe_url_config=url_config,
    )
    with pool:
        if (
            pool.process(unsafe, scope=ScanScope.OUTPUT, timeout=120).decision
            is not Action.REDACT
        ):
            raise RuntimeError("process warm-up did not sanitize unsafe URL")
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as callers:
            results = tuple(
                callers.map(
                    lambda _: pool.process(
                        unsafe,
                        scope=ScanScope.OUTPUT,
                        timeout=120,
                    ),
                    range(process_requests),
                )
            )
        process_seconds = time.perf_counter() - started
    if any(item.decision is not Action.REDACT for item in results):
        raise RuntimeError("process benchmark did not sanitize unsafe URL")

    mib = size / (1024 * 1024)
    return {
        **{
            f"{name}_mib_per_second": mib / median(values)
            for name, values in durations.items()
        },
        "unsafe_peak_mib": peak_bytes / (1024 * 1024),
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
    parser.add_argument("--min-unsafe-throughput-mib-s", type=float, default=2.5)
    parser.add_argument("--max-peak-mib", type=float, default=128.0)
    parser.add_argument(
        "--min-process-requests-per-second",
        type=float,
        default=0.5,
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
        result["near_miss_mib_per_second"],
        result["safe_at_end_mib_per_second"],
    ) < args.min_throughput_mib_s:
        raise SystemExit("unsafe URL throughput gate failed")
    if min(
        result["unsafe_at_end_mib_per_second"],
        result["metadata_host_at_end_mib_per_second"],
        result["overlapping_schemes_mib_per_second"],
    ) < args.min_unsafe_throughput_mib_s:
        raise SystemExit("unsafe URL redaction throughput gate failed")
    if result["unsafe_peak_mib"] > args.max_peak_mib:
        raise SystemExit("unsafe URL memory gate failed")
    if (
        result["process_requests_per_second"]
        < args.min_process_requests_per_second
    ):
        raise SystemExit("unsafe URL process gate failed")


if __name__ == "__main__":
    main()
