import ast
from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile
import unittest

import llm_ffw


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "EXAMPLES.md"
README = ROOT / "README.md"
PYTHON_BLOCK = re.compile(r"```python\n(.*?)\n```", re.DOTALL)


class DocumentedExampleTests(unittest.TestCase):
    def test_readme_python_blocks_compile_and_use_public_root_imports(self) -> None:
        document = README.read_text(encoding="utf-8")
        blocks = PYTHON_BLOCK.findall(document)
        self.assertEqual(len(blocks), 39)
        public_names = frozenset(llm_ffw.__all__)

        for index, code in enumerate(blocks, start=1):
            with self.subTest(example=index):
                tree = ast.parse(code, filename=f"README.md block {index}")
                for node in ast.walk(tree):
                    if not (
                        isinstance(node, ast.ImportFrom)
                        and node.module == "llm_ffw"
                    ):
                        continue
                    for imported in node.names:
                        self.assertIn(imported.name, public_names)
                        self.assertTrue(hasattr(llm_ffw, imported.name))

    def test_every_python_block_is_a_complete_runnable_program(self) -> None:
        document = EXAMPLES.read_text(encoding="utf-8")
        blocks = PYTHON_BLOCK.findall(document)
        self.assertEqual(len(blocks), 12)
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
