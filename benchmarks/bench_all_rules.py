"""Benchmark every text rule together with bounded production concurrency."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import sys
from threading import Lock
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.all_rules_data import (
    ALL_TEXT_RULE_IDS,
    BANNED_MARKER,
    TextScenario,
    build_text_scenarios,
)
from benchmarks.bench_manager_reload import _MemorySampler
from llm_ffw import (
    AuthorizationHeaderConfig,
    BannedSubstring,
    BannedSubstringCatalog,
    EmailAddressConfig,
    IBANConfig,
    IPAddressConfig,
    JSONOutputConfig,
    JWTTokenConfig,
    MACAddressConfig,
    PaymentCardConfig,
    PrivateKeyConfig,
    ProcessScannerPool,
    ProcessScannerPoolConfig,
    RepetitionConfig,
    ScanScope,
    ScannerConfig,
    UnsafeURLConfig,
)


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    scenario_id: str
    profile: str
    scope: str
    characters: int
    utf8_bytes: int
    workers: int
    concurrency: int
    requests: int
    catalog_patterns: int
    enabled_text_rules: int
    cold_start_ms: float
    warmup_ms: float
    elapsed_seconds: float
    requests_per_second: float
    aggregate_mib_per_second: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    service_p50_ms: float
    queue_wait_p95_ms: float
    peak_tree_rss_mib: float
    peak_processes: int
    completed: int
    rejected: int
    timed_out: int
    failed: int
    finding_counts: dict[str, int]


def _catalog(pattern_count: int) -> BannedSubstringCatalog:
    if isinstance(pattern_count, bool) or not isinstance(pattern_count, int):
        raise TypeError("pattern_count must be an integer")
    if pattern_count <= 0:
        raise ValueError("pattern_count must be positive")
    patterns = [BannedSubstring("benchmark.primary", BANNED_MARKER)]
    patterns.extend(
        BannedSubstring(
            f"benchmark.pattern.{index:06d}",
            f"reserved_benchmark_literal_{index:06d}",
        )
        for index in range(1, pattern_count)
    )
    return BannedSubstringCatalog(
        "benchmark.all_rules",
        "1",
        tuple(patterns),
        (ScanScope.INPUT, ScanScope.OUTPUT),
    )


def _pool(
    *,
    size: int,
    workers: int,
    concurrency: int,
    max_tasks_per_child: int | None,
    catalog_patterns: int,
    admission_timeout: float,
) -> ProcessScannerPool:
    both = (ScanScope.INPUT, ScanScope.OUTPUT)
    return ProcessScannerPool(
        scanner_config=ScannerConfig(max_input_chars=size),
        pool_config=ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=concurrency,
            max_tasks_per_child=max_tasks_per_child,
            admission_timeout_seconds=admission_timeout,
        ),
        banned_substring_catalog=_catalog(catalog_patterns),
        json_output_config=JSONOutputConfig(max_document_chars=size),
        unsafe_url_config=UnsafeURLConfig(scopes=both),
        ip_address_config=IPAddressConfig(scopes=both),
        mac_address_config=MACAddressConfig(scopes=both),
        iban_config=IBANConfig(scopes=both),
        authorization_header_config=AuthorizationHeaderConfig(scopes=both),
        email_address_config=EmailAddressConfig(scopes=both),
        payment_card_config=PaymentCardConfig(scopes=both),
        private_key_config=PrivateKeyConfig(scopes=both),
        jwt_token_config=JWTTokenConfig(scopes=both),
        repetition_config=RepetitionConfig(scopes=both),
    )


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = (len(ordered) - 1) * percentile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = rank - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def run_benchmark(
    scenario: TextScenario,
    *,
    workers: int,
    concurrency: int,
    requests: int,
    max_tasks_per_child: int | None = 1_000,
    catalog_patterns: int = 1,
    request_timeout: float = 180.0,
    admission_timeout: float = 5.0,
    sample_interval_seconds: float = 0.01,
) -> BenchmarkResult:
    """Run one profile and return content-free throughput and lifecycle evidence."""

    if min(workers, concurrency, requests) <= 0:
        raise ValueError("workers, concurrency, and requests must be positive")
    if concurrency < workers:
        raise ValueError("concurrency must be at least workers")
    if request_timeout <= 0 or admission_timeout < 0:
        raise ValueError("timeouts must be non-negative and request timeout positive")
    pool = _pool(
        size=len(scenario.text),
        workers=workers,
        concurrency=concurrency,
        max_tasks_per_child=max_tasks_per_child,
        catalog_patterns=catalog_patterns,
        admission_timeout=admission_timeout,
    )
    sampler = _MemorySampler(sample_interval_seconds)
    sampler.start()
    try:
        start_begin = time.perf_counter()
        pool.start()
        cold_start = time.perf_counter() - start_begin
        warm_begin = time.perf_counter()
        warm_result = pool.process(
            scenario.text, scope=scenario.scope, timeout=request_timeout
        )
        warmup = time.perf_counter() - warm_begin
    except BaseException:
        try:
            pool.shutdown(cancel_pending=True)
        finally:
            sampler.stop()
        raise
    expected = tuple(
        (item.rule_id, item.start, item.end, item.action)
        for item in scenario.expected
    )

    def fingerprint(result: object) -> tuple[tuple[str, int, int, str], ...]:
        findings = result.findings  # type: ignore[attr-defined]
        return tuple(
            (item.rule_id, item.span.start, item.span.end, item.action.value)
            for item in findings
        )

    warm_fingerprint = fingerprint(warm_result)
    if warm_fingerprint != expected:
        pool.shutdown(cancel_pending=True)
        sampler.stop()
        raise RuntimeError(
            f"scenario expectation mismatch for {scenario.scenario_id}: "
            f"expected {expected!r}, observed {warm_fingerprint!r}"
        )

    submitted_at: dict[int, float] = {}
    latencies: list[float] = []
    service_times: list[float] = []
    queue_waits: list[float] = []
    finding_counts: Counter[str] = Counter()
    failures: Counter[str] = Counter()
    lock = Lock()

    def invoke(request_id: int) -> None:
        service_started = time.perf_counter()
        queue_wait = service_started - submitted_at[request_id]
        try:
            result = pool.process(
                scenario.text,
                scope=scenario.scope,
                timeout=request_timeout,
                admission_timeout=admission_timeout,
            )
        except TimeoutError:
            with lock:
                failures["timed_out"] += 1
            return
        except BaseException as exc:
            name = type(exc).__name__
            with lock:
                failures["rejected" if "Saturated" in name else "failed"] += 1
            return
        finished = time.perf_counter()
        if fingerprint(result) != expected:
            with lock:
                failures["failed"] += 1
            return
        with lock:
            queue_waits.append(queue_wait)
            service_times.append(finished - service_started)
            latencies.append(finished - submitted_at[request_id])
            finding_counts.update(item.rule_id for item in result.findings)

    started = time.perf_counter()
    try:
        with ThreadPoolExecutor(max_workers=concurrency) as callers:
            futures = []
            for request_id in range(requests):
                submitted_at[request_id] = time.perf_counter()
                futures.append(callers.submit(invoke, request_id))
            for future in as_completed(futures, timeout=request_timeout * requests):
                future.result()
    finally:
        elapsed = time.perf_counter() - started
        pool.shutdown(cancel_pending=True)
        peak_rss, peak_processes = sampler.stop()

    completed = len(latencies)
    return BenchmarkResult(
        scenario_id=scenario.scenario_id,
        profile=scenario.profile,
        scope=scenario.scope.value,
        characters=len(scenario.text),
        utf8_bytes=len(scenario.text.encode("utf-8")),
        workers=workers,
        concurrency=concurrency,
        requests=requests,
        catalog_patterns=catalog_patterns,
        enabled_text_rules=len(ALL_TEXT_RULE_IDS),
        cold_start_ms=cold_start * 1_000,
        warmup_ms=warmup * 1_000,
        elapsed_seconds=elapsed,
        requests_per_second=completed / elapsed,
        aggregate_mib_per_second=(
            completed * len(scenario.text.encode("utf-8")) / (1024 * 1024) / elapsed
        ),
        latency_p50_ms=_percentile(latencies, 0.50) * 1_000,
        latency_p95_ms=_percentile(latencies, 0.95) * 1_000,
        latency_p99_ms=_percentile(latencies, 0.99) * 1_000,
        service_p50_ms=_percentile(service_times, 0.50) * 1_000,
        queue_wait_p95_ms=_percentile(queue_waits, 0.95) * 1_000,
        peak_tree_rss_mib=peak_rss / (1024 * 1024),
        peak_processes=peak_processes,
        completed=completed,
        rejected=failures["rejected"],
        timed_out=failures["timed_out"],
        failed=failures["failed"],
        finding_counts=dict(sorted(finding_counts.items())),
    )


def _csv_ints(value: str) -> tuple[int, ...]:
    try:
        values = tuple(int(item) for item in value.split(","))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected comma-separated integers") from exc
    if not values or any(item <= 0 for item in values):
        raise argparse.ArgumentTypeError("values must be positive")
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=_csv_ints, default=(8_000_000,))
    parser.add_argument(
        "--profiles",
        default=(
            "clean-input,clean-output-json,invalid-output-json,"
            "sparse-input,dense-input,adversarial-near-miss-input"
        ),
    )
    parser.add_argument("--workers", type=_csv_ints, default=(1, 2, 4))
    parser.add_argument("--concurrency-multiplier", type=int, default=2)
    parser.add_argument("--requests-per-worker", type=int, default=2)
    parser.add_argument("--catalog-patterns", type=_csv_ints, default=(1,))
    parser.add_argument("--max-tasks-per-child", type=int, default=1_000)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--memory-sample-ms", type=float, default=10.0)
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    if args.concurrency_multiplier <= 0 or args.requests_per_worker <= 0:
        parser.error("concurrency and request multipliers must be positive")
    selected = set(args.profiles.split(","))
    records: list[dict[str, object]] = []
    for size in args.sizes:
        scenarios = {
            item.scenario_id: item for item in build_text_scenarios(size)
        }
        unknown = selected - scenarios.keys()
        if unknown:
            parser.error(f"unknown profiles: {','.join(sorted(unknown))}")
        for scenario_id in sorted(selected):
            for catalog_patterns in args.catalog_patterns:
                for workers in args.workers:
                    if workers > (os.cpu_count() or 1):
                        continue
                    result = run_benchmark(
                        scenarios[scenario_id],
                        workers=workers,
                        concurrency=workers * args.concurrency_multiplier,
                        requests=workers * args.requests_per_worker,
                        max_tasks_per_child=args.max_tasks_per_child,
                        catalog_patterns=catalog_patterns,
                        request_timeout=args.timeout,
                        sample_interval_seconds=args.memory_sample_ms / 1_000,
                    )
                    record = asdict(result)
                    records.append(record)
                    print(json.dumps(record, sort_keys=True))
    if args.json_output is not None:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps({"schema_version": 1, "results": records}, indent=2) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
