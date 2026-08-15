"""Benchmark bounded JSON validation at the production payload envelope."""

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
    JSONOutputConfig,
    JSONOutputRule,
    ProcessScannerPool,
    ProcessScannerPoolConfig,
    Scanner,
    ScannerConfig,
    ScanScope,
)
from llm_ffw.rules.secrets import SecretsRule


def _json_string(size: int, *, escape_dense: bool = False) -> str:
    if size < 2:
        raise ValueError("size must be at least 2")
    inner_size = size - 2
    if not escape_dense:
        inner = "a" * inner_size
    else:
        pairs, remainder = divmod(inner_size, 2)
        inner = ('\\"' * pairs) + ("a" if remainder else "")
    return '"' + inner + '"'


def _json_with_secret(size: int) -> str:
    secret = "sk-" + ("A" * 20)
    prefix = '{"token":"' + secret + '","payload":"'
    suffix = '"}'
    filler_size = size - len(prefix) - len(suffix)
    if filler_size < 0:
        raise ValueError("size is too small for the redaction workload")
    return prefix + ("a" * filler_size) + suffix


def benchmark(
    *,
    size: int,
    rounds: int,
    workers: int,
    concurrency: int,
    process_requests: int,
) -> dict[str, float]:
    config = JSONOutputConfig(max_document_chars=size)
    scanner_config = ScannerConfig(max_input_chars=size)
    firewall = Firewall(
        scanner=Scanner(
            rules=(SecretsRule(), JSONOutputRule(config)),
            config=scanner_config,
        )
    )
    valid = _json_string(size)
    escape_dense = _json_string(size, escape_dense=True)
    invalid_at_end = _json_string(size - 1) + "x"
    redacted = _json_with_secret(size)
    requests = (
        ("valid", valid, Action.ALLOW),
        ("escape_dense", escape_dense, Action.ALLOW),
        ("invalid_at_end", invalid_at_end, Action.BLOCK),
        ("redacted", redacted, Action.REDACT),
    )
    durations: dict[str, list[float]] = {name: [] for name, _, _ in requests}
    for round_number in range(rounds):
        ordered = (
            requests[round_number % len(requests) :]
            + requests[: round_number % len(requests)]
        )
        for name, text, expected in ordered:
            started = time.perf_counter()
            result = firewall.process(text, scope=ScanScope.OUTPUT)
            durations[name].append(time.perf_counter() - started)
            if result.decision is not expected:
                raise RuntimeError("unexpected direct JSON benchmark decision")

    tracemalloc.start()
    measured = firewall.process(redacted, scope=ScanScope.OUTPUT)
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    if measured.decision is not Action.REDACT:
        raise RuntimeError("redacted JSON memory workload was not sanitized")

    pool = ProcessScannerPool(
        scanner_config=scanner_config,
        pool_config=ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=max(workers, concurrency),
        ),
        json_output_config=config,
    )
    with pool:
        if (
            pool.process(redacted, scope=ScanScope.OUTPUT, timeout=120).decision
            is not Action.REDACT
        ):
            raise RuntimeError("process warm-up did not sanitize JSON")
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as callers:
            results = tuple(
                callers.map(
                    lambda _: pool.process(
                        redacted,
                        scope=ScanScope.OUTPUT,
                        timeout=120,
                    ),
                    range(process_requests),
                )
            )
        process_seconds = time.perf_counter() - started
    if any(item.decision is not Action.REDACT for item in results):
        raise RuntimeError("process benchmark did not sanitize JSON")

    mib = size / (1024 * 1024)
    return {
        "valid_mib_per_second": mib / median(durations["valid"]),
        "escape_dense_mib_per_second": (
            mib / median(durations["escape_dense"])
        ),
        "invalid_at_end_mib_per_second": (
            mib / median(durations["invalid_at_end"])
        ),
        "redacted_mib_per_second": mib / median(durations["redacted"]),
        "redacted_peak_mib": peak_bytes / (1024 * 1024),
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
    parser.add_argument(
        "--min-redacted-throughput-mib-s",
        type=float,
        default=2.5,
    )
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
        result["valid_mib_per_second"],
        result["escape_dense_mib_per_second"],
        result["invalid_at_end_mib_per_second"],
    ) < args.min_throughput_mib_s:
        raise SystemExit("JSON throughput gate failed")
    if (
        result["redacted_mib_per_second"]
        < args.min_redacted_throughput_mib_s
    ):
        raise SystemExit("JSON redaction throughput gate failed")
    if result["redacted_peak_mib"] > args.max_peak_mib:
        raise SystemExit("JSON memory gate failed")
    if (
        result["process_requests_per_second"]
        < args.min_process_requests_per_second
    ):
        raise SystemExit("JSON process gate failed")


if __name__ == "__main__":
    main()
