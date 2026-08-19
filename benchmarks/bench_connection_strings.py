"""Benchmark opt-in connection-string inspection at the payload envelope."""

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
    ConnectionStringConfig,
    ConnectionStringRule,
    ProcessScannerPool,
    ProcessScannerPoolConfig,
    RuleEngine,
    RuleScanner,
    RuleScannerConfig,
    ScanScope,
)
from llm_ffw.rules.secrets import SecretsRule


_PASSWORD = "synthetic-db-password-123"


def _sized_suffix(size: int, suffix: str, fill: str = "a") -> str:
    if len(suffix) > size:
        raise ValueError("size is too small for benchmark suffix")
    return fill * (size - len(suffix)) + suffix


def benchmark(
    *,
    size: int,
    rounds: int,
    workers: int,
    concurrency: int,
    process_requests: int,
) -> dict[str, float]:
    config = ConnectionStringConfig()
    scanner_config = RuleScannerConfig(max_input_chars=size)
    firewall = RuleEngine(
        scanner=RuleScanner(
            rules=(SecretsRule(), ConnectionStringRule(config)),
            config=scanner_config,
        )
    )
    uri_text = _sized_suffix(
        size,
        f"\npostgres://benchmark.user:{_PASSWORD}@db.example/prod",
    )
    keyword_text = _sized_suffix(
        size,
        f"\nServer=db.example;Password={_PASSWORD};Database=prod",
    )
    oversized_prefix = "postgres://benchmark.user:"
    oversized_suffix = "@db.example/prod"
    oversized = (
        oversized_prefix
        + "A" * (size - len(oversized_prefix) - len(oversized_suffix))
        + oversized_suffix
    )
    workloads = (
        ("clean", "a" * size, Action.ALLOW),
        (
            "keyword_marker_dense",
            ("Password=value;" * ((size // 15) + 1))[:size],
            Action.ALLOW,
        ),
        (
            "placeholder_dense",
            (
                "postgres://user:%3Cpassword%3E@db.example/x\n"
                * ((size // 48) + 1)
            )[:size],
            Action.ALLOW,
        ),
        ("uri_at_end", uri_text, Action.REDACT),
        ("keyword_at_end", keyword_text, Action.REDACT),
        ("oversized", oversized, Action.REDACT),
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
            result = firewall.process(text, scope=ScanScope.INPUT)
            durations[name].append(time.perf_counter() - started)
            if result.decision is not expected:
                raise RuntimeError(
                    f"unexpected connection-string decision for {name}: "
                    f"{result.decision.value}"
                )

    tracemalloc.start()
    measured = firewall.process(uri_text, scope=ScanScope.INPUT)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if measured.decision is not Action.REDACT:
        raise RuntimeError("connection-string memory workload was not sanitized")

    pool = ProcessScannerPool(
        scanner_config=scanner_config,
        pool_config=ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=max(workers, concurrency),
        ),
        connection_string_config=config,
    )
    with pool:
        if (
            pool.process(uri_text, scope=ScanScope.INPUT, timeout=120).decision
            is not Action.REDACT
        ):
            raise RuntimeError("process warm-up did not sanitize credential")
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as callers:
            results = tuple(
                callers.map(
                    lambda _: pool.process(
                        uri_text,
                        scope=ScanScope.INPUT,
                        timeout=120,
                    ),
                    range(process_requests),
                )
            )
        process_seconds = time.perf_counter() - started
    if any(item.decision is not Action.REDACT for item in results):
        raise RuntimeError("process benchmark did not sanitize credential")

    mib = size / (1024 * 1024)
    return {
        **{
            f"{name}_mib_per_second": mib / median(values)
            for name, values in durations.items()
        },
        "valid_peak_mib": peak_bytes / (1024 * 1024),
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
        raise SystemExit("connection-string throughput gate failed")
    if result["valid_peak_mib"] > args.max_peak_mib:
        raise SystemExit("connection-string memory gate failed")
    if (
        result["process_requests_per_second"]
        < args.min_process_requests_per_second
    ):
        raise SystemExit("connection-string process gate failed")


if __name__ == "__main__":
    main()
