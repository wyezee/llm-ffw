"""Benchmark balanced scan-and-redact policy without printing corpus data."""

import argparse
from pathlib import Path
from statistics import median
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.synthetic_data import build_dataset
from llm_ffw import Action, Firewall, Scanner, ScannerConfig


def benchmark(size: int, rounds: int) -> tuple[float, float, int]:
    dataset = build_dataset(size)
    firewall = Firewall(scanner=Scanner(config=ScannerConfig(max_input_chars=size)))
    durations: list[float] = []
    finding_count = 0
    for _ in range(rounds):
        started = time.perf_counter()
        result = firewall.process(dataset.text)
        durations.append(time.perf_counter() - started)
        if result.decision is not Action.REDACT or result.processed_text is None:
            raise RuntimeError("balanced policy did not produce redacted text")
        finding_count = len(result.findings)
    seconds = median(durations)
    throughput = (size / (1024 * 1024)) / seconds if seconds else float("inf")
    return seconds, throughput, finding_count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=8_000_000)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--min-throughput-mib-s", type=float)
    args = parser.parse_args()
    if args.size <= 0 or args.rounds <= 0:
        parser.error("--size and --rounds must be positive")
    if args.min_throughput_mib_s is not None and args.min_throughput_mib_s <= 0:
        parser.error("--min-throughput-mib-s must be positive")
    seconds, throughput, count = benchmark(args.size, args.rounds)
    print(f"median_seconds={seconds:.6f}")
    print(f"throughput_mib_s={throughput:.2f}")
    print(f"findings={count}")
    if (
        args.min_throughput_mib_s is not None
        and throughput < args.min_throughput_mib_s
    ):
        raise SystemExit(
            "performance gate failed: "
            f"{throughput:.2f} MiB/s < {args.min_throughput_mib_s:.2f} MiB/s"
        )


if __name__ == "__main__":
    main()
