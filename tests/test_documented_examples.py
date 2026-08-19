from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "EXAMPLES.md"
PYTHON_BLOCK = re.compile(r"```python\n(.*?)\n```", re.DOTALL)


class DocumentedExampleTests(unittest.TestCase):
    def test_every_python_block_is_a_complete_runnable_program(self) -> None:
        document = EXAMPLES.read_text(encoding="utf-8")
        blocks = PYTHON_BLOCK.findall(document)
        self.assertEqual(len(blocks), 9)
        environment = os.environ.copy()
        existing_path = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            str(ROOT)
            if not existing_path
            else str(ROOT) + os.pathsep + existing_path
        )

        for index, code in enumerate(blocks, start=1):
            with self.subTest(example=index):
                with tempfile.TemporaryDirectory(
                    prefix=f"llm-ffw-example-{index}-"
                ) as temporary:
                    script = Path(temporary) / "example.py"
                    script.write_text(code, encoding="utf-8")
                    completed = subprocess.run(
                        [sys.executable, str(script)],
                        cwd=ROOT,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        env=environment,
                        check=False,
                    )
                self.assertEqual(
                    completed.returncode,
                    0,
                    msg=(
                        f"EXAMPLES.md Python block {index} failed\n"
                        f"stdout:\n{completed.stdout}\n"
                        f"stderr:\n{completed.stderr}"
                    ),
                )


if __name__ == "__main__":
    unittest.main()
