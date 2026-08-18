"""Benchmark private-key inspection at the production payload envelope."""

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
    PrivateKeyConfig,
    PrivateKeyRule,
    ProcessScannerPool,
    ProcessScannerPoolConfig,
    RuleScanner,
    RuleScannerConfig,
    ScanScope,
)
from llm_ffw.rules.secrets import SecretsRule


def _sized_suffix(size: int, suffix: str, fill: str = "a") -> str:
    if len(suffix) > size:
        raise ValueError("size is too small for benchmark suffix")
    repeats, remainder = divmod(size - len(suffix), len(fill))
    return (fill * repeats) + fill[:remainder] + suffix


def _synthetic_block() -> str:
    return (
        "-----BEGIN PRIVATE KEY-----\n"
        + ("QUJDREVGR0hJSktMTU5PUA==\n" * 8)
        + "-----END PRIVATE KEY-----"
    )


def benchmark(
    *, size: int, rounds: int, workers: int, concurrency: int,
    process_requests: int,
) -> dict[str, float]:
    rule_config = PrivateKeyConfig()
    scanner_config = RuleScannerConfig(max_input_chars=size)
    firewall = RuleEngine(
        scanner=RuleScanner(
            rules=(SecretsRule(), PrivateKeyRule(rule_config)),
            config=scanner_config,
        )
    )
    block = _synthetic_block()
    workloads = (
        ("clean", "a" * size, Action.ALLOW),
        (
            "unknown_marker_dense",
            _sized_suffix(size, "", "-----BEGIN CERTIFICATE-----"),
            Action.ALLOW,
        ),
        (
            "incomplete_at_end",
            _sized_suffix(size, "-----BEGIN PRIVATE KEY-----\nQUJD"),
            Action.REDACT,
        ),
        ("key_at_end", _sized_suffix(size, block), Action.REDACT),
    )
    durations: dict[str, list[float]] = {name: [] for name, _, _ in workloads}
    for round_number in range(rounds):
        ordered = (
            workloads[round_number % len(workloads):]
            + workloads[:round_number % len(workloads)]
        )
        for name, text, expected in ordered:
            started = time.perf_counter()
            result = firewall.process(text, scope=ScanScope.OUTPUT)
            durations[name].append(time.perf_counter() - started)
            if result.decision is not expected:
                raise RuntimeError("unexpected private-key benchmark decision")

    key_text = workloads[-1][1]
    tracemalloc.start()
    measured = firewall.process(key_text, scope=ScanScope.OUTPUT)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if measured.decision is not Action.REDACT:
        raise RuntimeError("private-key memory workload was not sanitized")

    pool = ProcessScannerPool(
        scanner_config=scanner_config,
        pool_config=ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=max(workers, concurrency),
        ),
        private_key_config=rule_config,
    )
    with pool:
        if pool.process(
            key_text, scope=ScanScope.OUTPUT, timeout=120
        ).decision is not Action.REDACT:
            raise RuntimeError("process warm-up did not sanitize private key")
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as callers:
            results = tuple(
                callers.map(
                    lambda _: pool.process(
                        key_text, scope=ScanScope.OUTPUT, timeout=120
                    ),
                    range(process_requests),
                )
            )
        process_seconds = time.perf_counter() - started
    if any(item.decision is not Action.REDACT for item in results):
        raise RuntimeError("process benchmark did not sanitize private key")

    mib = size / (1024 * 1024)
    return {
        **{
            f"{name}_mib_per_second": mib / median(values)
            for name, values in durations.items()
        },
        "key_peak_mib": peak_bytes / (1024 * 1024),
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
    parser.add_argument("--min-key-throughput-mib-s", type=float, default=2.5)
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
        result["unknown_marker_dense_mib_per_second"],
    ) < args.min_throughput_mib_s:
        raise SystemExit("private-key non-match throughput gate failed")
    if min(
        result["incomplete_at_end_mib_per_second"],
        result["key_at_end_mib_per_second"],
    ) < args.min_key_throughput_mib_s:
        raise SystemExit("private-key sanitization throughput gate failed")
    if result["key_peak_mib"] > args.max_peak_mib:
        raise SystemExit("private-key memory gate failed")
    if result["process_requests_per_second"] < args.min_process_requests_per_second:
        raise SystemExit("private-key process gate failed")


if __name__ == "__main__":
    main()
