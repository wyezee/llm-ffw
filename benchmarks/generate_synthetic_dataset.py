"""Generate a deterministic secret-scanner corpus without LLM or network calls."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.synthetic_data import SyntheticDataset, build_dataset


def write_dataset(dataset: SyntheticDataset, output_directory: Path) -> tuple[Path, Path]:
    """Write corpus text and a raw-secret-free expectation manifest."""

    output_directory.mkdir(parents=True, exist_ok=True)
    corpus_path = output_directory / "synthetic_secrets.txt"
    manifest_path = output_directory / "synthetic_secrets.manifest.json"
    corpus_path.write_text(dataset.text, encoding="utf-8", newline="")
    manifest = {
        "schema_version": 1,
        "generator": "deterministic-local-catalog",
        "uses_llm": False,
        "uses_network": False,
        "catalog_id": dataset.catalog_id,
        "catalog_version": dataset.catalog_version,
        "characters": len(dataset.text),
        "utf8_bytes": len(dataset.text.encode("utf-8")),
        "sha256": dataset.sha256,
        "expected_findings": [
            {
                "signature_id": item.signature_id,
                "provider": item.provider,
                "prefix": item.prefix,
                "span": {"start": item.start, "end": item.end},
            }
            for item in dataset.expected_findings
        ],
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="",
    )
    return corpus_path, manifest_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=8_000_000)
    parser.add_argument("--matches-per-prefix", type=int, default=1)
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path("benchmarks/generated"),
    )
    args = parser.parse_args()
    dataset = build_dataset(
        args.size,
        matches_per_prefix=args.matches_per_prefix,
    )
    corpus_path, manifest_path = write_dataset(dataset, args.output_directory)
    print(f"corpus={corpus_path}")
    print(f"manifest={manifest_path}")
    print(f"characters={len(dataset.text)}")
    print(f"expected_findings={len(dataset.expected_findings)}")
    print(f"sha256={dataset.sha256}")


if __name__ == "__main__":
    main()
