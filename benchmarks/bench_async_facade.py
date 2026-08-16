"""Benchmark bounded concurrent requests through AsyncLLMFirewall."""

import argparse
import asyncio
from dataclasses import dataclass
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.synthetic_data import build_dataset
from llm_ffw import (
    Action,
    AsyncLLMFirewall,
    ProcessScannerPoolConfig,
    ScannerConfig,
)


@dataclass(frozen=True, slots=True)
class AsyncBenchmarkResult:
    seconds: float
    requests_per_second: float
    aggregate_mib_per_second: float
    findings_per_request: int
    event_loop_ticks: int


async def benchmark_async_facade(
    *,
    size: int,
    workers: int,
    concurrency: int,
    requests: int,
    max_tasks_per_child: int,
) -> AsyncBenchmarkResult:
    """Run validated async requests without printing inspected content."""

    if min(size, workers, concurrency, requests, max_tasks_per_child) <= 0:
        raise ValueError("benchmark arguments must be positive")
    if concurrency < workers:
        raise ValueError("concurrency must be at least workers")
    dataset = build_dataset(size)
    expected_findings = len(dataset.expected_findings)
    firewall = AsyncLLMFirewall(
        scanner_config=ScannerConfig(max_input_chars=size),
        pool_config=ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=concurrency,
            max_tasks_per_child=max_tasks_per_child,
            admission_timeout_seconds=5.0,
        ),
        request_timeout_seconds=120.0,
    )
    tick_count = 0
    stop_ticks = asyncio.Event()

    async def tick() -> None:
        nonlocal tick_count
        while not stop_ticks.is_set():
            await asyncio.sleep(0.001)
            tick_count += 1

    async with firewall:
        warm = await firewall.sanitize_input_result(dataset.text)
        if len(warm.findings) != expected_findings:
            raise RuntimeError("async warm-up finding count changed")
        ticker = asyncio.create_task(tick())
        started = time.perf_counter()
        completed = 0
        try:
            while completed < requests:
                batch_size = min(concurrency, requests - completed)
                results = await asyncio.gather(
                    *(
                        firewall.sanitize_input_result(dataset.text)
                        for _ in range(batch_size)
                    )
                )
                for result in results:
                    if result.decision is not Action.REDACT:
                        raise RuntimeError("async policy did not redact request")
                    if len(result.findings) != expected_findings:
                        raise RuntimeError("async finding count changed")
                completed += batch_size
        finally:
            elapsed = time.perf_counter() - started
            stop_ticks.set()
            await ticker

    aggregate_mib = size * requests / (1024 * 1024)
    return AsyncBenchmarkResult(
        seconds=elapsed,
        requests_per_second=requests / elapsed,
        aggregate_mib_per_second=aggregate_mib / elapsed,
        findings_per_request=expected_findings,
        event_loop_ticks=tick_count,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=8_000_000)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--requests", type=int, default=16)
    parser.add_argument("--max-tasks-per-child", type=int, default=4)
    parser.add_argument("--min-requests-per-second", type=float)
    args = parser.parse_args()
    if (
        args.min_requests_per_second is not None
        and args.min_requests_per_second <= 0
    ):
        parser.error("--min-requests-per-second must be positive")
    try:
        result = asyncio.run(
            benchmark_async_facade(
                size=args.size,
                workers=args.workers,
                concurrency=args.concurrency,
                requests=args.requests,
                max_tasks_per_child=args.max_tasks_per_child,
            )
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(f"requests={args.requests}")
    print(f"seconds={result.seconds:.6f}")
    print(f"requests_per_second={result.requests_per_second:.2f}")
    print(f"aggregate_mib_per_second={result.aggregate_mib_per_second:.2f}")
    print(f"findings_per_request={result.findings_per_request}")
    print(f"event_loop_ticks={result.event_loop_ticks}")
    if result.event_loop_ticks <= 0:
        raise SystemExit("async benchmark event loop did not remain responsive")
    if (
        args.min_requests_per_second is not None
        and result.requests_per_second < args.min_requests_per_second
    ):
        raise SystemExit(
            "async performance gate failed: "
            f"{result.requests_per_second:.2f} requests/s < "
            f"{args.min_requests_per_second:.2f} requests/s"
        )


if __name__ == "__main__":
    main()
