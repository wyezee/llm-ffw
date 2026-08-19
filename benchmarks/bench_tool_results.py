"""Benchmark deterministic typed tool-result validation."""

import argparse
from pathlib import Path
from statistics import median
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm_ffw import (
    ToolCall,
    ToolResult,
    ToolResultBatch,
    ToolResultConfig,
    ToolResultRule,
)


def benchmark(*, rounds: int, batch_size: int) -> dict[str, float]:
    valid = ToolResultBatch(
        (ToolCall("search", {"query": "Pune"}, "call-1"),),
        (
            ToolResult(
                "call-1",
                [{"type": "text", "text": "bounded synthetic answer"}],
                "search",
            ),
        ),
    )
    invalid = ToolResultBatch(
        (ToolCall("search", {"query": "Pune"}, "call-1"),),
        (ToolResult("unmatched", "answer", "search"),),
    )
    unsafe = ToolResultBatch(
        (ToolCall("search", {"query": "Pune"}, "call-1"),),
        (ToolResult("call-1", "sk-" + "A" * 20, "search"),),
    )
    relaxed = ToolResultConfig(
        max_nodes=100_000,
        max_array_items=10_000,
    )
    oversized = ToolResultBatch(
        (ToolCall("batch", {}, "call-2"),),
        (
            ToolResult(
                "call-2",
                [{"index": index} for index in range(10_000)],
                "batch",
                limits=relaxed,
            ),
        ),
        limits=relaxed,
    )
    rule = ToolResultRule(
        ToolResultConfig(max_nodes=1_000, max_array_items=10_000)
    )

    valid_durations: list[float] = []
    invalid_durations: list[float] = []
    unsafe_durations: list[float] = []
    oversized_durations: list[float] = []
    for _ in range(rounds):
        started = time.perf_counter()
        for _ in range(batch_size):
            if rule.validate(valid):
                raise RuntimeError("valid tool result was rejected")
        valid_durations.append(time.perf_counter() - started)

        started = time.perf_counter()
        for _ in range(batch_size):
            if not rule.validate(invalid):
                raise RuntimeError("invalid tool result was accepted")
        invalid_durations.append(time.perf_counter() - started)

        started = time.perf_counter()
        for _ in range(batch_size):
            finding = rule.validate(unsafe)
            if (
                not finding
                or finding[0].metadata["reason"]
                != "content_policy_violation"
            ):
                raise RuntimeError("unsafe tool-result content was accepted")
        unsafe_durations.append(time.perf_counter() - started)

        started = time.perf_counter()
        finding = rule.validate(oversized)
        oversized_durations.append(time.perf_counter() - started)
        if not finding or finding[0].metadata["reason"] != "node_limit_exceeded":
            raise RuntimeError("oversized tool result did not fail closed")

    return {
        "valid_batches_per_second": batch_size / median(valid_durations),
        "invalid_batches_per_second": batch_size / median(invalid_durations),
        "unsafe_batches_per_second": batch_size / median(unsafe_durations),
        "oversized_p95_proxy_milliseconds": max(oversized_durations) * 1_000,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=7)
    parser.add_argument("--batch-size", type=int, default=20_000)
    parser.add_argument("--min-valid-batches-per-second", type=float, default=20_000)
    parser.add_argument("--min-invalid-batches-per-second", type=float, default=50_000)
    parser.add_argument("--min-unsafe-batches-per-second", type=float, default=20_000)
    parser.add_argument("--max-oversized-milliseconds", type=float, default=20.0)
    args = parser.parse_args()
    result = benchmark(rounds=args.rounds, batch_size=args.batch_size)
    for key, value in result.items():
        print(f"{key}={value:.6f}")
    if result["valid_batches_per_second"] < args.min_valid_batches_per_second:
        raise SystemExit("valid tool-result throughput gate failed")
    if result["invalid_batches_per_second"] < args.min_invalid_batches_per_second:
        raise SystemExit("invalid tool-result throughput gate failed")
    if result["unsafe_batches_per_second"] < args.min_unsafe_batches_per_second:
        raise SystemExit("unsafe tool-result throughput gate failed")
    if result["oversized_p95_proxy_milliseconds"] > args.max_oversized_milliseconds:
        raise SystemExit("oversized tool-result latency gate failed")


if __name__ == "__main__":
    main()
