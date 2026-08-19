# LLM FFW examples

These examples track the current source tree, including changelog entries under
`Unreleased`. Use the matching Git tag for a published package version. Every
Python block is a complete program and is executed by the documentation
regression test. All credentials, addresses, and identifiers are deterministic
synthetic values.

Use one long-lived `Firewall` per application process. The synchronous and
asynchronous facades own worker processes, so executable programs need the
normal `if __name__ == "__main__"` entry-point guard.

## Sanitize input with the production facade

`Firewall` is the recommended entry point. Structured results expose the
effective decision and disclosure-safe findings alongside forwardable text.

```python
from llm_ffw import Action, Firewall

def main() -> None:
    synthetic_secret = "sk-" + "A" * 20
    prompt = f"Summarize this request using {synthetic_secret}."

    with Firewall() as firewall:
        result = firewall.sanitize_input_result(prompt)

    assert result.text == "Summarize this request using [REDACTED]."
    assert result.decision is Action.REDACT
    assert [finding.rule_id for finding in result.findings] == [
        "secrets.detected"
    ]

if __name__ == "__main__":
    main()
```

## Reusable model I/O hook

Own one hook for the application process and call it on both sides of the
model boundary. Choose the preset at deployment time rather than per request;
`FirewallConfig.privacy_input()` and `FirewallConfig.json_api()` can replace
the baseline preset below when those protections are required.
`FirewallConfig.all_text_rules()` is the explicit full-coverage option for
deployments whose outputs are always JSON.

```python
from llm_ffw import Firewall, FirewallConfig, SanitizationResult

class ModelIOHook:
    def __init__(self, config: FirewallConfig) -> None:
        self._firewall = Firewall.from_config(config)

    def start(self) -> None:
        self._firewall.start()

    def before_model(self, text: str) -> SanitizationResult:
        return self._firewall.sanitize_input_result(text)

    def after_model(self, text: str) -> SanitizationResult:
        return self._firewall.sanitize_output_result(text)

    def close(self) -> None:
        self._firewall.close()

def call_model(safe_prompt: str) -> str:
    assert "sk-" not in safe_prompt
    return "Model response contains sk-" + "B" * 20

def main() -> None:
    hook = ModelIOHook(FirewallConfig.default())
    hook.start()
    try:
        prompt = "Summarize this token: sk-" + "A" * 20
        input_result = hook.before_model(prompt)
        model_output = call_model(input_result.text)
        output_result = hook.after_model(model_output)
    finally:
        hook.close()

    assert input_result.text == "Summarize this token: [REDACTED]"
    assert output_result.text == "Model response contains [REDACTED]"
    assert input_result.findings[0].rule_id == "secrets.detected"
    assert output_result.findings[0].rule_id == "secrets.detected"

if __name__ == "__main__":
    main()
```

## Activate the privacy preset

The baseline rules remain enabled. The preset additionally enables input-side
email, IP-address, MAC-address, IBAN, and phone-number inspection.

```python
from llm_ffw import Firewall, FirewallConfig

def main() -> None:
    prompt = "Contact alex@example.com from +999000000000001."

    with Firewall.from_config(FirewallConfig.privacy_input()) as firewall:
        result = firewall.sanitize_input_result(prompt)

    assert result.text == "Contact [REDACTED] from [REDACTED]."
    assert {finding.rule_id for finding in result.findings} == {
        "pii.email_address",
        "pii.phone_number",
    }

if __name__ == "__main__":
    main()
```

## Require JSON output and inspect URLs

The JSON API preset activates output JSON validation and unsafe-URL inspection
in both directions. A blocked exception contains findings, but never stores the
submitted content.

```python
from llm_ffw import ContentBlockedError, Firewall, FirewallConfig

def main() -> None:
    with Firewall.from_config(FirewallConfig.json_api()) as firewall:
        safe_input = firewall.sanitize_input(
            "Fetch http://169.254.169.254/latest/meta-data"
        )
        assert safe_input == "Fetch [REDACTED]"

        try:
            firewall.sanitize_output('{"score": NaN}')
        except ContentBlockedError as exc:
            assert [finding.rule_id for finding in exc.findings] == [
                "output.json.validity"
            ]
        else:
            raise AssertionError("invalid JSON was not blocked")

if __name__ == "__main__":
    main()
```

## Enable every text rule

The full-coverage preset enables every self-contained text rule across every
scope it supports. It also requires valid JSON output, so use it only for
deployments with that output contract. A deployment-owned banned-substring
catalog can be supplied separately when needed.

```python
from llm_ffw import Action, Firewall, FirewallConfig

def main() -> None:
    output = '{"contact":"alex@example.com"}'
    with Firewall.from_config(FirewallConfig.all_text_rules()) as firewall:
        result = firewall.sanitize_output_result(output)

    assert result.text == '{"contact":"[REDACTED]"}'
    assert result.decision is Action.REDACT
    assert [finding.rule_id for finding in result.findings] == [
        "pii.email_address"
    ]

if __name__ == "__main__":
    main()
```

## Fail closed on blocked or unavailable inspection

Treat a policy block and an unavailable scanner as different operational
events, but never forward the original text in either case. Both exception
types expose bounded, disclosure-safe metadata.

```python
from llm_ffw import (
    ContentBlockedError,
    Firewall,
    FirewallUnavailableError,
    STRICT_POLICY,
)

def main() -> None:
    synthetic_secret = "sk-" + "F" * 20
    firewall = Firewall(policy=STRICT_POLICY)

    with firewall:
        try:
            firewall.sanitize_input(synthetic_secret)
        except ContentBlockedError as exc:
            assert exc.findings[0].rule_id == "secrets.detected"
        else:
            raise AssertionError("strict policy did not block the secret")

    try:
        firewall.sanitize_input("safe text")
    except FirewallUnavailableError as exc:
        assert exc.cause_type
    else:
        raise AssertionError("closed firewall accepted a request")

if __name__ == "__main__":
    main()
```

## Choose detection-only or in-process enforcement

`RuleScanner` only detects. `RuleEngine` applies policy to scanner findings in
the same process. These APIs do not create worker processes.

```python
from llm_ffw import Action, RuleEngine, RuleScanner, ScanScope

synthetic_secret = "sk-" + "A" * 20
scanner = RuleScanner()

findings = scanner.scan(synthetic_secret, scope=ScanScope.INPUT)
assert [finding.rule_id for finding in findings] == ["secrets.detected"]
assert findings[0].redacted_preview == "[REDACTED:openai_api_key]"

result = RuleEngine(scanner=scanner).process(
    synthetic_secret,
    scope=ScanScope.INPUT,
)
assert result.decision is Action.REDACT
assert result.processed_text == "[REDACTED]"
```

## Use the async production facade

`AsyncFirewall` preserves the production policy and process isolation without
blocking the event loop while waiting for a worker.

```python
import asyncio

from llm_ffw import AsyncFirewall

async def handle() -> None:
    synthetic_secret = "sk-" + "A" * 20
    async with AsyncFirewall() as firewall:
        safe_text = await firewall.sanitize_input(synthetic_secret)
    assert safe_text == "[REDACTED]"

if __name__ == "__main__":
    asyncio.run(handle())
```

## Scan chunked input

`AUTO` streaming preserves normal rule semantics. It emits safe text early
when possible and otherwise buffers until `finish()`.

```python
from llm_ffw import RuleEngine

engine = RuleEngine()
stream = engine.stream()
parts = []
try:
    parts.append(stream.feed("Token sk-"))
    parts.append(stream.feed("A" * 20))
    parts.append(stream.finish())
except BaseException:
    stream.cancel()
    raise

assert "".join(parts) == "Token [REDACTED]"
assert [finding.rule_id for finding in stream.findings] == [
    "secrets.detected"
]
```

## Reload a deployment-owned secret catalog

Catalog reloads replace one immutable worker generation with another and drain
requests using the previous generation. A reload receives a complete new
additional or replacement catalog snapshot, not an incremental patch.

```python
import string

from llm_ffw import FirewallManager, SecretCatalog, SecretSignature

BOUNDARY_CHARS = string.ascii_letters + string.digits + "._-"

def catalog(version: str, prefix: str) -> SecretCatalog:
    return SecretCatalog(
        catalog_id="example.enterprise.secrets",
        version=version,
        signatures=(
            SecretSignature(
                signature_id=f"example.enterprise.token.{version}",
                provider="example",
                secret_type="api_token",
                prefixes=(prefix,),
                suffix_chars=string.ascii_uppercase + string.digits,
                min_suffix_chars=12,
                max_suffix_chars=12,
                boundary_chars=BOUNDARY_CHARS,
                source="https://example.invalid/security/token-format",
            ),
        ),
    )

def main() -> None:
    first = catalog("1", "corp_live_")
    second = catalog("2", "corp_next_")

    with FirewallManager(additional_secret_catalog=first) as manager:
        assert manager.sanitize_input("corp_live_ABCDEFGHIJKL") == "[REDACTED]"
        capabilities = manager.reload(additional_secret_catalog=second)
        assert capabilities.secret_catalog.version == "2"
        assert manager.sanitize_input("corp_next_ABCDEFGHIJKL") == "[REDACTED]"

if __name__ == "__main__":
    main()
```

## Validate structured tool traffic

Declare tool schemas once, validate each model-selected call before execution,
then validate linked tool results before returning them to model context.

```python
from llm_ffw import ToolCallRule, ToolDefinition, ToolResultRule

def main() -> None:
    calls = ToolCallRule(
        (
            ToolDefinition(
                name="get_weather",
                parameters={
                    "type": "object",
                    "properties": {
                        "city": {"type": "string"},
                    },
                    "required": ["city"],
                    "additionalProperties": False,
                },
            ),
        )
    )
    safe_call = calls.enforce(
        calls.build_call(
            "get_weather",
            {"city": "Pune"},
            call_id="call-1",
        )
    )

    results = ToolResultRule()
    returned = results.build_result(
        call_id="call-1",
        name="get_weather",
        content="Sunny, 28 C",
    )
    safe_batch = results.enforce(
        results.build_batch((safe_call,), (returned,))
    )

    assert safe_call.name == "get_weather"
    assert safe_batch.results[0].content == "Sunny, 28 C"

if __name__ == "__main__":
    main()
```

## Control the process pool directly

Use `ProcessScannerPool` only when the application needs explicit admission,
timeout, or shutdown control. `process()` applies policy; `scan()` only returns
findings.

```python
from llm_ffw import Action, ProcessScannerPool, ProcessScannerPoolConfig

def main() -> None:
    pool = ProcessScannerPool(
        pool_config=ProcessScannerPoolConfig(
            max_workers=1,
            max_in_flight=2,
        )
    )
    pool.start()
    try:
        synthetic_secret = "sk-" + "A" * 20
        result = pool.process(synthetic_secret, timeout=5.0)
        assert result.decision is Action.REDACT
        assert result.processed_text == "[REDACTED]"
    finally:
        pool.shutdown(cancel_pending=True)

if __name__ == "__main__":
    main()
```

For provider-neutral tool-call and tool-result validation, see the dedicated
sections in the [README](README.md#opt-in-tool-call-validation). Those APIs
validate structured objects rather than text and therefore sit outside the
input/output facade lifecycle.
