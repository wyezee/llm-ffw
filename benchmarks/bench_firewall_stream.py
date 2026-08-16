"""Benchmark incremental FirewallStream against balanced batch inspection."""

import argparse
from pathlib import Path
from statistics import median
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.synthetic_data import build_dataset
from llm_ffw import (
    BALANCED_POLICY,
    Firewall,
    FirewallStream,
    ScanScope,
    Scanner,
    ScannerConfig,
    StreamMode,
)
from llm_ffw.rules import SecretsRule


def _stream_once(
    firewall: Firewall,
    text: str,
    chunk_size: int,
) -> tuple[str, FirewallStream]:
    stream = firewall.stream(mode=StreamMode.INCREMENTAL)
    parts: list[str] = []
    for start in range(0, len(text), chunk_size):
        parts.append(stream.feed(text[start : start + chunk_size]))
    parts.append(stream.finish())
    return "".join(parts), stream


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=8_000_000)
    parser.add_argument("--chunk-size", type=int, default=16_384)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--max-overhead-percent", type=float, default=15.0)
    args = parser.parse_args()
    if args.size <= 0:
        parser.error("--size must be positive")
    if args.chunk_size <= 0:
        parser.error("--chunk-size must be positive")
    if args.rounds <= 0:
        parser.error("--rounds must be positive")
    if args.max_overhead_percent < 0:
        parser.error("--max-overhead-percent must not be negative")

    text = build_dataset(args.size).text
    firewall = Firewall(
        scanner=Scanner(
            rules=(SecretsRule(),),
            config=ScannerConfig(max_input_chars=len(text)),
        ),
        policy=BALANCED_POLICY,
    )
    oracle = firewall.process(text, scope=ScanScope.INPUT)
    if oracle.processed_text is None:
        raise RuntimeError("batch oracle unexpectedly blocked the dataset")

    batch_durations: list[float] = []
    stream_durations: list[float] = []
    last_stream: FirewallStream | None = None
    for _ in range(args.rounds):
        started = time.perf_counter()
        batch = firewall.process(text, scope=ScanScope.INPUT)
        batch_durations.append(time.perf_counter() - started)
        if batch != oracle:
            raise RuntimeError("batch oracle changed between deterministic runs")

        started = time.perf_counter()
        streamed_text, stream = _stream_once(firewall, text, args.chunk_size)
        stream_durations.append(time.perf_counter() - started)
        if streamed_text != oracle.processed_text:
            raise RuntimeError("streaming output differs from batch oracle")
        if stream.findings != oracle.findings:
            raise RuntimeError("streaming findings differ from batch oracle")
        last_stream = stream

    if last_stream is None:
        raise RuntimeError("streaming benchmark did not execute")
    batch_seconds = median(batch_durations)
    stream_seconds = median(stream_durations)
    overhead_percent = (
        (stream_seconds - batch_seconds) / batch_seconds * 100
        if batch_seconds
        else 0.0
    )
    verdict = (
        "firewall_stream_performance_pass"
        if overhead_percent <= args.max_overhead_percent
        else "firewall_stream_performance_fail"
    )
    print(f"size={len(text)}")
    print(f"chunk_size={args.chunk_size}")
    print(f"batch_seconds={batch_seconds:.6f}")
    print(f"stream_seconds={stream_seconds:.6f}")
    print(f"overhead_percent={overhead_percent:.2f}")
    print(f"max_buffered_chars={last_stream.max_buffered_chars}")
    print(f"findings={len(last_stream.findings)}")
    print(f"max_overhead_percent={args.max_overhead_percent:.2f}")
    print(f"verdict={verdict}")
    if overhead_percent > args.max_overhead_percent:
        raise SystemExit("FirewallStream overhead gate failed")


if __name__ == "__main__":
    main()
