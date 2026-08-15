"""Exercise repeated concurrent policy requests and forced worker recycling."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.synthetic_data import build_dataset
from llm_ffw import (
    Action,
    ProcessPoolState,
    ProcessScannerPool,
    ProcessScannerPoolConfig,
    ScannerConfig,
)


def run_soak(
    *,
    size: int,
    workers: int,
    concurrency: int,
    requests: int,
    max_tasks_per_child: int,
) -> tuple[float, float, float, int]:
    dataset = build_dataset(size)
    expected_findings = len(dataset.expected_findings)
    pool = ProcessScannerPool(
        scanner_config=ScannerConfig(max_input_chars=size),
        pool_config=ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=max(concurrency, workers),
            max_tasks_per_child=max_tasks_per_child,
            admission_timeout_seconds=5.0,
        ),
    )
    completed = 0
    started = time.perf_counter()
    with pool, ThreadPoolExecutor(max_workers=concurrency) as callers:
        while completed < requests:
            batch_size = min(concurrency, requests - completed)
            futures = [
                callers.submit(pool.process, dataset.text, timeout=120.0)
                for _ in range(batch_size)
            ]
            for future in futures:
                result = future.result(timeout=130.0)
                if result.decision is not Action.REDACT:
                    raise RuntimeError("balanced policy did not redact soak request")
                if result.processed_text is None:
                    raise RuntimeError("redacted soak result did not contain text")
                if len(result.findings) != expected_findings:
                    raise RuntimeError("soak finding count changed")
                completed += 1
        if pool.state is not ProcessPoolState.RUNNING:
            raise RuntimeError("process pool stopped during soak")
    elapsed = time.perf_counter() - started
    request_rate = requests / elapsed
    aggregate_mib = size * requests / (1024 * 1024)
    return elapsed, request_rate, aggregate_mib / elapsed, expected_findings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=8_000_000)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--requests", type=int, default=32)
    parser.add_argument("--max-tasks-per-child", type=int, default=4)
    parser.add_argument("--min-requests-per-second", type=float)
    args = parser.parse_args()
    positive = (
        args.size,
        args.workers,
        args.concurrency,
        args.requests,
        args.max_tasks_per_child,
    )
    if any(value <= 0 for value in positive):
        parser.error("size, workers, concurrency, requests, and recycling must be positive")
    if args.concurrency < args.workers:
        parser.error("--concurrency must be at least --workers")
    if (
        args.min_requests_per_second is not None
        and args.min_requests_per_second <= 0
    ):
        parser.error("--min-requests-per-second must be positive")

    elapsed, request_rate, throughput, findings = run_soak(
        size=args.size,
        workers=args.workers,
        concurrency=args.concurrency,
        requests=args.requests,
        max_tasks_per_child=args.max_tasks_per_child,
    )
    print(f"requests={args.requests}")
    print(f"seconds={elapsed:.6f}")
    print(f"requests_per_second={request_rate:.2f}")
    print(f"aggregate_mib_per_second={throughput:.2f}")
    print(f"findings_per_request={findings}")
    print(f"max_tasks_per_child={args.max_tasks_per_child}")
    if (
        args.min_requests_per_second is not None
        and request_rate < args.min_requests_per_second
    ):
        raise SystemExit(
            "performance gate failed: "
            f"{request_rate:.2f} requests/s < "
            f"{args.min_requests_per_second:.2f} requests/s"
        )


if __name__ == "__main__":
    main()
