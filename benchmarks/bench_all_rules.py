"""Benchmark every text rule together with bounded production concurrency."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
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
    RuleScannerConfig,
    UnsafeURLConfig,
)


DEFAULT_TEXT_RULE_IDS = frozenset(
    {
        "secrets.detected",
        "unicode.invisible_characters",
        "unicode.tag_smuggling",
        "pii.payment_card",
        "secrets.private_key",
        "secrets.jwt_token",
    }
)
_RULE_SETS = {
    "default": DEFAULT_TEXT_RULE_IDS,
    "all": ALL_TEXT_RULE_IDS,
}


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    rule_set: str
    round_index: int
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
    latency_samples_ms: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class BenchmarkSummary:
    rule_set: str
    scenario_id: str
    profile: str
    scope: str
    characters: int
    workers: int
    concurrency: int
    catalog_patterns: int
    rounds: int
    measured_requests: int
    median_requests_per_second: float
    median_aggregate_mib_per_second: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    max_peak_tree_rss_mib: float
    rejected: int
    timed_out: int
    failed: int


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
    rule_set: str,
) -> ProcessScannerPool:
    if rule_set not in _RULE_SETS:
        raise ValueError("rule_set must be 'default' or 'all'")
    common = {
        "scanner_config": RuleScannerConfig(max_input_chars=size),
        "pool_config": ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=concurrency,
            max_tasks_per_child=max_tasks_per_child,
            admission_timeout_seconds=admission_timeout,
        ),
    }
    if rule_set == "default":
        return ProcessScannerPool(**common)
    both = (ScanScope.INPUT, ScanScope.OUTPUT)
    return ProcessScannerPool(
        **common,
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
    rule_set: str = "all",
    round_index: int = 1,
) -> BenchmarkResult:
    """Run one profile and return content-free throughput and lifecycle evidence."""

    if min(workers, concurrency, requests) <= 0:
        raise ValueError("workers, concurrency, and requests must be positive")
    if concurrency < workers:
        raise ValueError("concurrency must be at least workers")
    if request_timeout <= 0 or admission_timeout < 0:
        raise ValueError("timeouts must be non-negative and request timeout positive")
    if rule_set not in _RULE_SETS:
        raise ValueError("rule_set must be 'default' or 'all'")
    if isinstance(round_index, bool) or not isinstance(round_index, int):
        raise TypeError("round_index must be an integer")
    if round_index <= 0:
        raise ValueError("round_index must be positive")
    pool = _pool(
        size=len(scenario.text),
        workers=workers,
        concurrency=concurrency,
        max_tasks_per_child=max_tasks_per_child,
        catalog_patterns=catalog_patterns,
        admission_timeout=admission_timeout,
        rule_set=rule_set,
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
    enabled_rule_ids = _RULE_SETS[rule_set]
    expected = tuple(
        (item.rule_id, item.start, item.end, item.action)
        for item in scenario.expected
        if item.rule_id in enabled_rule_ids
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
        rule_set=rule_set,
        round_index=round_index,
        scenario_id=scenario.scenario_id,
        profile=scenario.profile,
        scope=scenario.scope.value,
        characters=len(scenario.text),
        utf8_bytes=len(scenario.text.encode("utf-8")),
        workers=workers,
        concurrency=concurrency,
        requests=requests,
        catalog_patterns=catalog_patterns,
        enabled_text_rules=len(enabled_rule_ids),
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
        latency_samples_ms=tuple(item * 1_000 for item in latencies),
    )


def summarize_results(
    results: list[BenchmarkResult],
) -> tuple[BenchmarkSummary, ...]:
    """Aggregate repeated rounds without retaining any scanned content."""

    grouped: dict[tuple[object, ...], list[BenchmarkResult]] = {}
    for result in results:
        key = (
            result.rule_set,
            result.scenario_id,
            result.profile,
            result.scope,
            result.characters,
            result.workers,
            result.concurrency,
            result.catalog_patterns,
        )
        grouped.setdefault(key, []).append(result)
    summaries: list[BenchmarkSummary] = []
    for key, members in sorted(grouped.items(), key=lambda item: item[0]):
        samples = [
            sample
            for member in members
            for sample in member.latency_samples_ms
        ]
        summaries.append(
            BenchmarkSummary(
                rule_set=str(key[0]),
                scenario_id=str(key[1]),
                profile=str(key[2]),
                scope=str(key[3]),
                characters=int(key[4]),
                workers=int(key[5]),
                concurrency=int(key[6]),
                catalog_patterns=int(key[7]),
                rounds=len(members),
                measured_requests=sum(item.completed for item in members),
                median_requests_per_second=statistics.median(
                    item.requests_per_second for item in members
                ),
                median_aggregate_mib_per_second=statistics.median(
                    item.aggregate_mib_per_second for item in members
                ),
                latency_p50_ms=_percentile(samples, 0.50),
                latency_p95_ms=_percentile(samples, 0.95),
                latency_p99_ms=_percentile(samples, 0.99),
                max_peak_tree_rss_mib=max(
                    item.peak_tree_rss_mib for item in members
                ),
                rejected=sum(item.rejected for item in members),
                timed_out=sum(item.timed_out for item in members),
                failed=sum(item.failed for item in members),
            )
        )
    return tuple(summaries)


def environment_metadata() -> dict[str, object]:
    """Return reproducibility metadata without hostnames or user paths."""

    try:
        commit = subprocess.run(
            ("git", "rev-parse", "HEAD"),
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ("git", "status", "--porcelain"),
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout
        )
    except (OSError, subprocess.SubprocessError):
        commit = "unavailable"
        dirty = True
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "commit": commit,
        "dirty": dirty,
    }


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
    parser.add_argument("--rule-sets", default="default,all")
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--concurrency-multiplier", type=int, default=2)
    parser.add_argument("--requests-per-worker", type=int, default=2)
    parser.add_argument("--catalog-patterns", type=_csv_ints, default=(1,))
    parser.add_argument("--max-tasks-per-child", type=int, default=1_000)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--memory-sample-ms", type=float, default=10.0)
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    if (
        args.concurrency_multiplier <= 0
        or args.requests_per_worker <= 0
        or args.rounds <= 0
    ):
        parser.error("concurrency and request multipliers must be positive")
    selected = set(args.profiles.split(","))
    selected_rule_sets = set(args.rule_sets.split(","))
    unknown_rule_sets = selected_rule_sets - _RULE_SETS.keys()
    if unknown_rule_sets:
        parser.error(
            f"unknown rule sets: {','.join(sorted(unknown_rule_sets))}"
        )
    results: list[BenchmarkResult] = []
    for size in args.sizes:
        scenarios = {
            item.scenario_id: item for item in build_text_scenarios(size)
        }
        unknown = selected - scenarios.keys()
        if unknown:
            parser.error(f"unknown profiles: {','.join(sorted(unknown))}")
        for scenario_id in sorted(selected):
            for rule_set in sorted(selected_rule_sets):
                pattern_counts = (
                    args.catalog_patterns if rule_set == "all" else (0,)
                )
                for catalog_patterns in pattern_counts:
                    for workers in args.workers:
                        if workers > (os.cpu_count() or 1):
                            continue
                        for round_index in range(1, args.rounds + 1):
                            result = run_benchmark(
                                scenarios[scenario_id],
                                workers=workers,
                                concurrency=(
                                    workers * args.concurrency_multiplier
                                ),
                                requests=workers * args.requests_per_worker,
                                max_tasks_per_child=args.max_tasks_per_child,
                                catalog_patterns=catalog_patterns,
                                request_timeout=args.timeout,
                                sample_interval_seconds=(
                                    args.memory_sample_ms / 1_000
                                ),
                                rule_set=rule_set,
                                round_index=round_index,
                            )
                            results.append(result)
                            print(json.dumps(asdict(result), sort_keys=True))
    summaries = summarize_results(results)
    for summary in summaries:
        print(json.dumps({"summary": asdict(summary)}, sort_keys=True))
    if args.json_output is not None:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "environment": environment_metadata(),
                    "results": [asdict(item) for item in results],
                    "summaries": [asdict(item) for item in summaries],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
