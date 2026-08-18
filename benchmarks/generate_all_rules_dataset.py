"""Write deterministic all-rule corpora and a disclosure-safe manifest."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.all_rules_data import build_text_scenarios, manifest


def write_dataset(size: int, output_directory: Path) -> tuple[Path, ...]:
    scenarios = build_text_scenarios(size)
    output_directory.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for scenario in scenarios:
        path = output_directory / f"{scenario.scenario_id}.txt"
        path.write_text(scenario.text, encoding="utf-8", newline="")
        paths.append(path)
    manifest_path = output_directory / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest(scenarios), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="",
    )
    paths.append(manifest_path)
    return tuple(paths)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=8_000_000)
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path("benchmarks/generated/all-rules"),
    )
    args = parser.parse_args()
    for path in write_dataset(args.size, args.output_directory):
        print(f"written={path}")


if __name__ == "__main__":
    main()
