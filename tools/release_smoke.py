"""Build a wheel and verify it from an isolated virtual environment."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import venv


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.18.0"
SMOKE_CODE = """
import llm_ffw
import llm_ffw.async_facade as async_facade_module
import llm_ffw.config as config_module
import llm_ffw.engine as engine_module
import llm_ffw.facade as facade_module
import llm_ffw.manager as manager_module
import llm_ffw.policy as policy_module
from importlib.metadata import files, metadata, version
from inspect import signature
from typing import get_type_hints
from llm_ffw import (
    __version__,
    Action,
    AsyncFirewall,
    AsyncFirewallManager,
    BidiControlRule,
    AuthorizationHeaderConfig,
    AuthorizationHeaderRule,
    ConnectionStringConfig,
    ConnectionStringRule,
    RuleEngine,
    FirewallStream,
    EmailAddressConfig,
    EmailAddressRule,
    ExternalResourceConfig,
    ExternalResourceRule,
    IPAddressConfig,
    IPAddressRule,
    IBANConfig,
    IBANRule,
    FirewallConfig,
    MACAddressConfig,
    MACAddressRule,
    Firewall,
    FirewallManager,
    PaymentCardRule,
    PhoneNumberConfig,
    PhoneNumberRule,
    RepetitionConfig,
    RepetitionRule,
    RuleActivation,
    ScanScope,
    RuleScanner,
    RuleScannerConfig,
    SanitizationResult,
    StreamMode,
    ToolCall,
    ToolCallRule,
    ToolDefinition,
    ToolResult,
    ToolResultBatch,
    ToolResultRule,
    UnsafeURLConfig,
    available_presets,
    available_rules,
    config_from_preset,
)
from llm_ffw.rules import SecretsRule

assert version("llm-ffw") == "0.18.0"
assert __version__ == version("llm-ffw")
assert metadata("llm-ffw").get_all("Requires-Dist") is None
assert metadata("llm-ffw")["License-Expression"] == "Apache-2.0"
assert "Development Status :: 4 - Beta" in metadata("llm-ffw").get_all(
    "Classifier"
)
assert any(str(path).endswith("licenses/LICENSE") for path in files("llm-ffw"))
assert any(str(path) == "llm_ffw/py.typed" for path in files("llm-ffw"))
assert Firewall.__module__ == "llm_ffw.facade"
assert AsyncFirewall.__module__ == "llm_ffw.async_facade"
assert AsyncFirewallManager.__module__ == "llm_ffw.async_facade"
for module, name in (
    (llm_ffw, "LLMFirewall"),
    (llm_ffw, "AsyncLLMFirewall"),
    (llm_ffw, "LLMFirewallManager"),
    (llm_ffw, "AsyncLLMFirewallManager"),
    (llm_ffw, "Scanner"),
    (llm_ffw, "ScannerConfig"),
    (facade_module, "LLMFirewall"),
    (async_facade_module, "AsyncLLMFirewall"),
    (async_facade_module, "AsyncLLMFirewallManager"),
    (manager_module, "LLMFirewallManager"),
    (engine_module, "Scanner"),
    (config_module, "ScannerConfig"),
    (policy_module, "Firewall"),
):
    assert not hasattr(module, name)
    assert name not in module.__all__
for public_method in (
    Firewall.sanitize_input,
    AsyncFirewall.sanitize_input,
    RuleEngine.process,
    RuleScanner.scan,
):
    hints = get_type_hints(public_method)
    assert hints["text"] is str
    assert "return" in hints
assert SanitizationResult.__module__ == "llm_ffw.facade"
assert FirewallConfig.__module__ == "llm_ffw.facade_config"
assert FirewallStream.__module__ == "llm_ffw.streaming"
rule_descriptors = available_rules()
assert len(rule_descriptors) == 22
assert tuple(item.rule_id for item in rule_descriptors) == tuple(
    sorted(item.rule_id for item in rule_descriptors)
)
assert {
    item.rule_id
    for item in rule_descriptors
    if item.requires_deployment_value
} == {"content.banned_substrings", "tools.call.validity"}
assert next(
    item for item in rule_descriptors if item.rule_id == "tools.call.validity"
).activation is RuleActivation.EXPLICIT
preset_descriptors = available_presets()
assert tuple(item.preset_id for item in preset_descriptors) == (
    "all-text",
    "default",
    "json-api",
    "privacy-input",
)
all_text_descriptor = preset_descriptors[0]
assert len(all_text_descriptor.rules) == 19
assert all(
    item.rule_id != "content.banned_substrings"
    for item in all_text_descriptor.rules
)
assert config_from_preset("all-text") == FirewallConfig.all_text_rules()
facade_parameters = signature(Firewall).parameters
assert "additional_secret_catalog" in facade_parameters
assert "replacement_secret_catalog" in facade_parameters
assert "secret_catalog" not in facade_parameters
assert "ip_address_config" in facade_parameters
assert "mac_address_config" in facade_parameters
assert "iban_config" in facade_parameters
assert "authorization_header_config" in facade_parameters
assert "connection_string_config" in facade_parameters
assert "external_resource_config" in facade_parameters
assert "repetition_config" in facade_parameters
assert "email_address_config" in facade_parameters
assert "phone_number_config" in facade_parameters
capabilities = Firewall().capabilities()
assert capabilities.rule_count == 7
assert tuple(rule.rule_id for rule in capabilities.rules) == (
    "pii.payment_card",
    "secrets.detected",
    "secrets.jwt_token",
    "secrets.private_key",
    "unicode.bidi_controls",
    "unicode.invisible_characters",
    "unicode.tag_smuggling",
)
assert capabilities.payment_card.max_candidates == 128
assert capabilities.private_key.max_candidates == 32
assert capabilities.jwt_token.max_candidates == 128
assert capabilities.secret_catalog.signature_count == 28
assert "sk-" not in repr(capabilities)
assert "https://" not in repr(capabilities)
manager = FirewallManager()
assert manager.capabilities() == capabilities
assert callable(manager.sanitize_input_result)
assert callable(manager.sanitize_output_result)
manager.close()
configured = Firewall.from_config(FirewallConfig.default())
assert configured.capabilities() == capabilities
configured.close()
assert callable(AsyncFirewallManager.from_config)
url_firewall = Firewall(unsafe_url_config=UnsafeURLConfig())
assert url_firewall.capabilities().unsafe_url.max_candidates == 128
assert any(
    rule.rule_id == "url.unsafe"
    for rule in url_firewall.capabilities().rules
)
url_firewall.close()
resource_firewall = Firewall(
    external_resource_config=ExternalResourceConfig(
        allowed_hostname_suffixes=("assets.example",)
    )
)
assert resource_firewall.capabilities().external_resource.max_candidates == 128
assert any(
    rule.rule_id == ExternalResourceRule.RULE_ID
    for rule in resource_firewall.capabilities().rules
)
assert "assets.example" not in repr(resource_firewall.capabilities())
resource_firewall.close()
ip_firewall = Firewall(ip_address_config=IPAddressConfig())
assert ip_firewall.capabilities().ip_address.max_candidates == 128
assert any(
    rule.rule_id == IPAddressRule.RULE_ID
    for rule in ip_firewall.capabilities().rules
)
ip_firewall.close()
mac_firewall = Firewall(mac_address_config=MACAddressConfig())
assert mac_firewall.capabilities().mac_address.max_candidates == 128
assert any(
    rule.rule_id == MACAddressRule.RULE_ID
    for rule in mac_firewall.capabilities().rules
)
mac_firewall.close()
iban_firewall = Firewall(iban_config=IBANConfig())
assert iban_firewall.capabilities().iban.max_candidates == 128
assert iban_firewall.capabilities().iban.registry_release == "102"
assert any(
    rule.rule_id == IBANRule.RULE_ID
    for rule in iban_firewall.capabilities().rules
)
iban_firewall.close()
authorization_firewall = Firewall(
    authorization_header_config=AuthorizationHeaderConfig()
)
assert (
    authorization_firewall.capabilities().authorization_header.max_candidates
    == 128
)
assert any(
    rule.rule_id == AuthorizationHeaderRule.RULE_ID
    for rule in authorization_firewall.capabilities().rules
)
assert authorization_firewall.capabilities().authorization_header.schemes == (
    "basic",
    "bearer",
)
authorization_firewall.close()
connection_firewall = Firewall(
    connection_string_config=ConnectionStringConfig()
)
assert BidiControlRule().rule_id == "unicode.bidi_controls"
assert connection_firewall.capabilities().connection_string.max_candidates == 128
assert any(
    rule.rule_id == ConnectionStringRule.RULE_ID
    for rule in connection_firewall.capabilities().rules
)
connection_firewall.close()
connection_result = RuleEngine(
    scanner=RuleScanner(rules=(ConnectionStringRule(),))
).process("postgres://user:synthetic-db-password-123@db.example/prod")
assert connection_result.decision is Action.REDACT
assert connection_result.processed_text == (
    "postgres://user:[REDACTED]@db.example/prod"
)
authorization_result = RuleEngine(
    scanner=RuleScanner(rules=(AuthorizationHeaderRule(),))
).process("Authorization: Bearer synthetic_bearer_token_123456")
assert authorization_result.decision is Action.REDACT
assert authorization_result.processed_text == "Authorization: Bearer [REDACTED]"
repetition_firewall = Firewall(repetition_config=RepetitionConfig())
assert repetition_firewall.capabilities().repetition.max_findings == 64
assert any(
    rule.rule_id == RepetitionRule.RULE_ID
    for rule in repetition_firewall.capabilities().rules
)
repetition_firewall.close()
repetition_result = RuleEngine(
    scanner=RuleScanner(rules=(RepetitionRule(),))
).process("repeat " * 64)
assert repetition_result.decision is Action.REVIEW
assert repetition_result.processed_text == "repeat " * 64
email_firewall = Firewall(email_address_config=EmailAddressConfig())
assert email_firewall.capabilities().email_address.max_candidates == 128
assert any(
    rule.rule_id == EmailAddressRule.RULE_ID
    for rule in email_firewall.capabilities().rules
)
email_firewall.close()
phone_firewall = Firewall(phone_number_config=PhoneNumberConfig())
assert phone_firewall.capabilities().phone_number.max_candidates == 128
assert any(
    rule.rule_id == PhoneNumberRule.RULE_ID
    for rule in phone_firewall.capabilities().rules
)
phone_firewall.close()
tool_definition = ToolDefinition(
    "lookup",
    {
        "type": "object",
        "properties": {"query": {"type": "string"}},
        "required": ["query"],
        "additionalProperties": False,
    },
)
tool_call = ToolCall("lookup", {"query": "synthetic"}, "call-1")
assert ToolCallRule((tool_definition,)).validate(tool_call) == ()
tool_batch = ToolResultBatch(
    (tool_call,),
    (ToolResult("call-1", "synthetic result", "lookup"),),
)
assert ToolResultRule().validate(tool_batch) == ()
synthetic = "sk-" + "A" * 20
result = RuleEngine().process(synthetic, scope=ScanScope.INPUT)
assert result.decision is Action.REDACT
assert result.processed_text == "[REDACTED]"
assert synthetic not in result.processed_text
assert len(result.findings) == 1
invisible = RuleEngine().process("hello\u200bworld", scope=ScanScope.INPUT)
assert invisible.decision is Action.REMOVE
assert invisible.processed_text == "helloworld"
tagged = "".join(chr(0xE0000 + ord(char)) for char in "hidden")
tag_result = RuleEngine().process("visible" + tagged, scope=ScanScope.INPUT)
assert tag_result.decision is Action.REMOVE
assert tag_result.processed_text == "visible"
payment = RuleEngine().process("Card 4242424242424242", scope=ScanScope.OUTPUT)
assert payment.decision is Action.REDACT
assert payment.processed_text == "Card [REDACTED]"
private_key = (
    "-----BEGIN PRIVATE KEY-----\\n"
    "QUJDREVGR0hJSktMTU5PUA==\\n"
    "-----END PRIVATE KEY-----"
)
key_result = RuleEngine().process(private_key, scope=ScanScope.OUTPUT)
assert key_result.decision is Action.REDACT
assert key_result.processed_text == "[REDACTED]"
assert private_key not in repr(key_result.findings)
jwt = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJzeW50aGV0aWMtdXNlciJ9."
    "c2lnbmF0dXJl"
)
jwt_result = RuleEngine().process(jwt, scope=ScanScope.INPUT)
assert jwt_result.decision is Action.REDACT
assert jwt_result.processed_text == "[REDACTED]"
assert jwt not in repr(jwt_result.findings)
streaming_firewall = RuleEngine(
    scanner=RuleScanner(rules=(SecretsRule(), PaymentCardRule()))
)
streaming_text = "Card 4242424242424242 and sk-" + "A" * 20
streaming_oracle = streaming_firewall.process(
    streaming_text,
    scope=ScanScope.INPUT,
)
stream = streaming_firewall.stream(mode=StreamMode.INCREMENTAL)
streaming_output = stream.feed(streaming_text[:13])
streaming_output += stream.feed(streaming_text[13:31])
streaming_output += stream.feed(streaming_text[31:])
streaming_output += stream.finish()
assert streaming_output == streaming_oracle.processed_text
assert stream.findings == streaming_oracle.findings
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
        _run(
            [
                str(python),
                "-I",
                str(ROOT / "tools" / "rc_acceptance.py"),
                "--workers",
                "1",
                "--concurrency",
                "2",
                "--rounds",
                "1",
                "--max-tasks-per-child",
                "4",
                "--max-p99-latency-ms",
                "10000",
            ],
            cwd=work,
            env=clean_env,
        )

    print(f"isolated_wheel_smoke=passed version={EXPECTED_VERSION}")


if __name__ == "__main__":
    main()
