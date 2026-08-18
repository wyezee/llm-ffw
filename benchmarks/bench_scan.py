"""Dependency-free microbenchmark for the default catalog scanning path."""

import argparse
from pathlib import Path
from statistics import median
import sys
import time

# Make the documented direct invocation work from a source checkout.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm_ffw import RuleScanner, RuleScannerConfig


def benchmark(size: int, rounds: int) -> tuple[float, float, int]:
    """Return median seconds, MiB/s, and finding count without printing input."""

    marker = "sk-" + "A1" * 16
    if size > len(marker):
        text = "x" * (size - len(marker) - 1) + " " + marker
    else:
        text = "x" * size
    scanner = RuleScanner(config=RuleScannerConfig(max_input_chars=len(text)))

    durations: list[float] = []
    finding_count = 0
    for _ in range(rounds):
        started = time.perf_counter()
        findings = scanner.scan(text)
        durations.append(time.perf_counter() - started)
        finding_count = len(findings)

    seconds = median(durations)
    throughput = (len(text) / (1024 * 1024)) / seconds if seconds else float("inf")
    return seconds, throughput, finding_count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=1_000_000)
    parser.add_argument("--rounds", type=int, default=5)
    args = parser.parse_args()
    if args.size <= 0 or args.rounds <= 0:
        parser.error("--size and --rounds must be positive")

    seconds, throughput, count = benchmark(args.size, args.rounds)
    print(f"median_seconds={seconds:.6f}")
    print(f"throughput_mib_s={throughput:.2f}")
    print(f"findings={count}")


if __name__ == "__main__":
    main()
