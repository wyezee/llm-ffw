"""Build a wheel and verify it from an isolated virtual environment."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import venv


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.1.0"
SMOKE_CODE = """
from importlib.metadata import files, metadata, version
from inspect import signature
from llm_ffw import Action, Firewall, LLMFirewall, LLMFirewallManager, ScanScope

assert version("llm-ffw") == "0.1.0"
assert metadata("llm-ffw").get_all("Requires-Dist") is None
assert metadata("llm-ffw")["License-Expression"] == "Apache-2.0"
assert any(str(path).endswith("licenses/LICENSE") for path in files("llm-ffw"))
assert LLMFirewall.__module__ == "llm_ffw.facade"
facade_parameters = signature(LLMFirewall).parameters
assert "additional_secret_catalog" in facade_parameters
assert "replacement_secret_catalog" in facade_parameters
assert "secret_catalog" not in facade_parameters
capabilities = LLMFirewall().capabilities()
assert capabilities.rule_count == 1
assert capabilities.secret_catalog.signature_count == 28
assert "sk-" not in repr(capabilities)
assert "https://" not in repr(capabilities)
manager = LLMFirewallManager()
assert manager.capabilities() == capabilities
manager.close()
synthetic = "sk-" + "A" * 20
result = Firewall().process(synthetic, scope=ScanScope.INPUT)
assert result.decision is Action.REDACT
assert result.processed_text == "[REDACTED]"
assert synthetic not in result.processed_text
assert len(result.findings) == 1
"""


def _venv_python(environment: Path) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=cwd, env=env, check=True)


def main() -> None:
    supported = (
        sys.version_info[:3] >= (3, 14, 7)
        and sys.version_info[:2] == (3, 14)
    )
    if not supported:
        raise RuntimeError("release smoke test requires Python >=3.14.7,<3.15")

    with tempfile.TemporaryDirectory(prefix="llm-ffw-release-") as temporary:
        work = Path(temporary)
        wheels = work / "wheels"
        wheels.mkdir()
        _run(
            [
                sys.executable,
                "-m",
                "pip",
                "--disable-pip-version-check",
                "wheel",
                "--no-deps",
                "--wheel-dir",
                str(wheels),
                str(ROOT),
            ],
            cwd=work,
        )
        built = tuple(wheels.glob("llm_ffw-*.whl"))
        if len(built) != 1 or EXPECTED_VERSION not in built[0].name:
            raise RuntimeError("wheel build did not produce the expected artifact")

        environment = work / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(environment)
        python = _venv_python(environment)
        clean_env = os.environ.copy()
        clean_env.pop("PYTHONPATH", None)
        clean_env["PYTHONNOUSERSITE"] = "1"
        _run(
            [
                str(python),
                "-m",
                "pip",
                "--disable-pip-version-check",
                "install",
                "--no-index",
                "--no-deps",
                str(built[0]),
            ],
            cwd=work,
            env=clean_env,
        )
        _run([str(python), "-I", "-c", SMOKE_CODE], cwd=work, env=clean_env)

    print(f"isolated_wheel_smoke=passed version={EXPECTED_VERSION}")


if __name__ == "__main__":
    main()
