"""Benchmark opt-in IP-address inspection at the production payload envelope."""

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
    Firewall,
    IPAddressConfig,
    IPAddressRule,
    ProcessScannerPool,
    ProcessScannerPoolConfig,
    Scanner,
    ScannerConfig,
    ScanScope,
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
    address_config = IPAddressConfig()
    scanner_config = ScannerConfig(max_input_chars=size)
    firewall = Firewall(
        scanner=Scanner(
            rules=(SecretsRule(), IPAddressRule(address_config)),
            config=scanner_config,
        )
    )
    workloads = (
        ("clean", "a" * size, Action.ALLOW),
        ("colon_dense", ":" * size, Action.ALLOW),
        ("dot_dense", "." * size, Action.ALLOW),
        (
            "invalid_at_end",
            _sized_suffix(size, " 999.999.999.999"),
            Action.ALLOW,
        ),
        (
            "ipv4_at_end",
            _sized_suffix(size, " 192.168.100.25"),
            Action.REDACT,
        ),
        (
            "ipv6_at_end",
            _sized_suffix(size, " 2001:db8::1234"),
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
            result = firewall.process(text, scope=ScanScope.INPUT)
            durations[name].append(time.perf_counter() - started)
            if result.decision is not expected:
                raise RuntimeError("unexpected IP-address benchmark decision")

    address_text = workloads[-1][1]
    tracemalloc.start()
    measured = firewall.process(address_text, scope=ScanScope.INPUT)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if measured.decision is not Action.REDACT:
        raise RuntimeError("IP-address memory workload was not sanitized")

    pool = ProcessScannerPool(
        scanner_config=scanner_config,
        pool_config=ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=max(workers, concurrency),
        ),
        ip_address_config=address_config,
    )
    with pool:
        if (
            pool.process(
                address_text,
                scope=ScanScope.INPUT,
                timeout=120,
            ).decision
            is not Action.REDACT
        ):
            raise RuntimeError("process warm-up did not sanitize IP address")
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as callers:
            results = tuple(
                callers.map(
                    lambda _: pool.process(
                        address_text,
                        scope=ScanScope.INPUT,
                        timeout=120,
                    ),
                    range(process_requests),
                )
            )
        process_seconds = time.perf_counter() - started
    if any(item.decision is not Action.REDACT for item in results):
        raise RuntimeError("process benchmark did not sanitize IP address")

    mib = size / (1024 * 1024)
    return {
        **{
            f"{name}_mib_per_second": mib / median(values)
            for name, values in durations.items()
        },
        "address_peak_mib": peak_bytes / (1024 * 1024),
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
    parser.add_argument("--min-address-throughput-mib-s", type=float, default=2.5)
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
        result["colon_dense_mib_per_second"],
        result["dot_dense_mib_per_second"],
        result["invalid_at_end_mib_per_second"],
    ) < args.min_throughput_mib_s:
        raise SystemExit("IP-address throughput gate failed")
    if min(
        result["ipv4_at_end_mib_per_second"],
        result["ipv6_at_end_mib_per_second"],
    ) < args.min_address_throughput_mib_s:
        raise SystemExit("IP-address redaction throughput gate failed")
    if result["address_peak_mib"] > args.max_peak_mib:
        raise SystemExit("IP-address memory gate failed")
    if (
        result["process_requests_per_second"]
        < args.min_process_requests_per_second
    ):
        raise SystemExit("IP-address process gate failed")


if __name__ == "__main__":
    main()
