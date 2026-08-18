"""Measure steady-state concurrent scans of a deterministic synthetic corpus."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from statistics import median
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.synthetic_data import build_dataset
from llm_ffw import (
    ProcessScannerPool,
    ProcessScannerPoolConfig,
    RuleScanner,
    RuleScannerConfig,
)


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    executor: str
    workers: int
    requests: int
    characters_per_request: int
    findings_per_request: int
    seconds: float
    requests_per_second: float
    aggregate_mib_per_second: float


def _scan(scanner: RuleScanner, text: str) -> int:
    return len(scanner.scan(text))


def benchmark_concurrency(
    executor: str,
    text: str,
    *,
    expected_findings: int,
    workers: int,
    requests: int,
    rounds: int = 1,
) -> BenchmarkResult:
    """Run a warmed concurrency scenario and validate every result count."""

    if executor not in {"serial", "thread", "process"}:
        raise ValueError("executor must be serial, thread, or process")
    if workers <= 0 or requests <= 0 or rounds <= 0:
        raise ValueError("workers, requests, and rounds must be positive")
    scanner = RuleScanner(config=RuleScannerConfig(max_input_chars=len(text)))
    durations: list[float] = []
    count_batches: list[list[int]] = []

    if executor == "serial":
        for _ in range(rounds):
            started = time.perf_counter()
            count_batches.append([_scan(scanner, text) for _ in range(requests)])
            durations.append(time.perf_counter() - started)
        actual_workers = 1
    elif executor == "thread":
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(lambda _: _scan(scanner, text), range(workers)))
            for _ in range(rounds):
                started = time.perf_counter()
                count_batches.append(
                    list(pool.map(lambda _: _scan(scanner, text), range(requests)))
                )
                durations.append(time.perf_counter() - started)
        actual_workers = workers
    else:
        pool_config = ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=max(workers, requests),
        )
        with ProcessScannerPool(
            scanner_config=RuleScannerConfig(max_input_chars=len(text)),
            pool_config=pool_config,
        ) as pool:
            warm_futures = [pool.submit(text) for _ in range(workers)]
            warm_counts = [len(future.result()) for future in warm_futures]
            if any(count != expected_findings for count in warm_counts):
                raise RuntimeError("process warm-up finding counts were inconsistent")
            for _ in range(rounds):
                started = time.perf_counter()
                futures = [pool.submit(text) for _ in range(requests)]
                count_batches.append(
                    [len(future.result()) for future in futures]
                )
                durations.append(time.perf_counter() - started)
        actual_workers = workers

    if any(
        count != expected_findings
        for counts in count_batches
        for count in counts
    ):
        raise RuntimeError("concurrent scan finding counts were inconsistent")
    elapsed = median(durations)
    total_mib = len(text) * requests / (1024 * 1024)
    return BenchmarkResult(
        executor=executor,
        workers=actual_workers,
        requests=requests,
        characters_per_request=len(text),
        findings_per_request=expected_findings,
        seconds=elapsed,
        requests_per_second=requests / elapsed if elapsed else float("inf"),
        aggregate_mib_per_second=total_mib / elapsed if elapsed else float("inf"),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=8_000_000)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--requests", type=int, default=8)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument(
        "--executors",
        default="serial,thread,process",
        help="comma-separated subset of serial,thread,process",
    )
    args = parser.parse_args()
    if args.size <= 0 or args.workers <= 0 or args.requests <= 0 or args.rounds <= 0:
        parser.error("--size, --workers, --requests, and --rounds must be positive")

    executors = tuple(item.strip() for item in args.executors.split(",") if item.strip())
    if not executors or any(item not in {"serial", "thread", "process"} for item in executors):
        parser.error("--executors must contain serial, thread, or process")
    dataset = build_dataset(args.size)
    expected_count = len(dataset.expected_findings)
    for executor in executors:
        result = benchmark_concurrency(
            executor,
            dataset.text,
            expected_findings=expected_count,
            workers=args.workers,
            requests=args.requests,
            rounds=args.rounds,
        )
        print(
            f"executor={result.executor} workers={result.workers} "
            f"requests={result.requests} seconds={result.seconds:.6f} "
            f"requests_per_second={result.requests_per_second:.2f} "
            f"aggregate_mib_per_second={result.aggregate_mib_per_second:.2f} "
            f"findings_per_request={result.findings_per_request}"
        )


if __name__ == "__main__":
    main()
