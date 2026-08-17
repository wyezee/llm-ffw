"""Write the optional expanded deterministic PII accuracy corpus."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.pii_accuracy import build_corpus, write_corpus


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("benchmarks/generated/pii_accuracy"),
    )
    args = parser.parse_args()
    corpus = build_corpus()
    corpus_path, manifest_path = write_corpus(corpus, args.output_dir)
    print(f"corpus_path={corpus_path}")
    print(f"manifest_path={manifest_path}")
    print(f"scenario_count={len(corpus.scenarios)}")
    print(f"sha256={corpus.sha256}")
    print("uses_llm=false")
    print("uses_network=false")


if __name__ == "__main__":
    main()
