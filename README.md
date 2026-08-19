# LLM FFW

**LLM FFW** (LLM Fast Firewall) is a high-speed deterministic rule engine for
scanning inputs entering and outputs leaving an LLM runtime.

The default scanner ships a secure baseline: `SecretsRule`, input-only
`InvisibleCharactersRule`, input-only `UnicodeTagSmugglingRule`,
both-scope `BidiControlRule`, `PaymentCardRule`, `PrivateKeyRule`, and
`JWTTokenRule`. It detects constrained
credential formats, armored private-key blocks, and structurally credible
compact JWTs; canonicalizes contextual invisible-character token obfuscation and non-RGI
Unicode tag runs; removes directional overrides while reporting other explicit
bidi controls; and redacts Luhn-valid payment-card candidates. Findings
retain original-text spans and safe category metadata rather than matched
values.

LLM FFW also provides opt-in `IPAddressRule`, `EmailAddressRule`,
`MACAddressRule`, `IBANRule`, and `PhoneNumberRule` privacy controls. They use bounded
deterministic parsing, default to input-only redaction under the balanced
policy, and remain disabled until configured. Provider-neutral `ToolCallRule`
and `ToolResultRule` validate bounded typed tool traffic before execution and
before results return to the model. `AuthorizationHeaderRule` redacts exact
Basic and Bearer credentials, `ConnectionStringRule` redacts credentials from
explicit URI and ADO/ODBC connection-string forms, and `RepetitionRule` reviews
conservative exact character, token, and line runs. `CredentialAssignmentRule`
redacts values assigned to high-confidence credential field names in env,
shell, YAML-like, and object-style forms. Output-only
`ExternalResourceRule` can redact non-allowlisted external Markdown/HTML image
URLs before a host renders them.

## Contents

- [Rule coverage and policy](#rule-coverage-and-policy)
- [Security boundary and limitations](#security-boundary-and-limitations)
- [Installation and quick start](#installation-and-quick-start)
- [Common recipes](#common-recipes)
- [Measured performance](#measured-performance)
- [Usage](#usage)
  - [Concurrency and object sharing](#concurrency-and-object-sharing)
  - [FastAPI lifespan integration](#fastapi-lifespan-integration)
  - [Results and failure handling](#results-and-failure-handling)
- [Facade configuration](#facade-configuration)
- [Rule configuration](#rule-configuration)
- [Versioned signature catalogs](#versioned-signature-catalogs)
- [Runtime catalog updates](#runtime-catalog-updates)
- [Development and validation](#development-and-validation)
- [Production process concurrency](#production-process-concurrency)
- [License](#license)

## Rule coverage and policy

`BALANCED_POLICY` is the default. Scope below means the scope selected by the
normal configuration or `FirewallConfig.all_text_rules()`; configurable rules
can be narrowed, and the input-only PII defaults can explicitly enable output
inspection. The library exposes 20 text rules plus two structured validators:

| Rule | Activation | Default scope | Balanced handling | Policy choices |
| --- | --- | --- | --- | --- |
| `SecretsRule` | Default | Both | Redact | Standard¹ |
| `InvisibleCharactersRule` | Default | Input | Remove² | Standard¹ |
| `UnicodeTagSmugglingRule` | Default | Input | Remove² | Standard¹ |
| `BidiControlRule` | Default | Both | Remove overrides; review other explicit controls² | Standard¹ |
| `PaymentCardRule` | Default | Both | Redact | Standard¹ |
| `PrivateKeyRule` | Default | Both | Redact | Standard¹ |
| `JWTTokenRule` | Default | Both | Redact | Standard¹ |
| `BannedSubstringsRule` | Opt-in catalog | Both by default | Catalog action; redact by default² | Per-entry action and Standard¹ override |
| `JSONOutputRule` | Opt-in | Output | Block | Review or block |
| `UnsafeURLRule` | Opt-in | Both | Redact | Standard¹ |
| `ExternalResourceRule` | Opt-in | Output | Redact | Standard¹ |
| `IPAddressRule` | Opt-in | Input; output configurable | Redact | Standard¹ |
| `MACAddressRule` | Opt-in | Input; output configurable | Redact | Standard¹ |
| `IBANRule` | Opt-in | Input; output configurable | Redact | Standard¹ |
| `AuthorizationHeaderRule` | Opt-in | Both | Redact | Standard¹ |
| `ConnectionStringRule` | Opt-in | Both | Redact | Standard¹ |
| `CredentialAssignmentRule` | Opt-in | Both | Redact | Standard¹ |
| `EmailAddressRule` | Opt-in | Input; output configurable | Redact | Standard¹ |
| `PhoneNumberRule` | Opt-in | Input; output configurable | Redact | Standard¹ |
| `RepetitionRule` | Opt-in | Both | Review² | Standard¹ |
| `ToolCallRule` | Explicit structured API | Tool call | Block finding | Outside text policy; host enforces |
| `ToolResultRule` | Explicit structured API | Tool result | Block finding | Outside text policy; host enforces |

¹ Standard policy choices are `ALLOW`, `REVIEW`, `REMOVE`, `REDACT`, and
`BLOCK`, selected per rule and scope with `PolicyOverride`. JSON validity is
deliberately restricted to `REVIEW` or `BLOCK`.

² The listed action describes an ordinary match. Malformed input, candidate
overflow, or another resource-limit condition can produce a fail-closed
`BLOCK` finding when the active policy does not override it.

The bundled alternatives are `STRICT_POLICY` and `AUDIT_POLICY`. A custom
immutable `FirewallPolicy` provides finer per-rule, per-scope control.

## Security boundary and limitations

LLM FFW provides deterministic, format-based inspection. It can enforce known
text shapes, configured literal catalogs, bounded structural rules, and typed
tool schemas. It does not determine intent, factual correctness, toxicity,
prompt-injection semantics, whether a credential is active, whether a URL is
reachable, or whether a tool actually ran. It is one enforcement layer, not a
replacement for authentication, authorization, network egress controls, tool
allowlisting, or application validation.

Exact formats have exact boundaries. Deliberate or accidental obfuscation,
unsupported Unicode transformations, local phone formats, non-catalog secrets,
and values outside a rule's documented grammar may not match. The default
scanner covers seven broadly useful rules; privacy and deployment-specific rules
remain opt-in to avoid silently changing legitimate data. Opt-in PII rules scan
input by default and inspect output only when their configured `scopes` include
`ScanScope.OUTPUT`.

Tool-call arguments and tool-result content are scanned by the deterministic
text baseline by default, in addition to structural validation. This blocks
known findings but does not establish that arguments are authorized for the
current user or that returned content is trustworthy. The host must retain those
authorization and trust decisions.

`Firewall` and its managers provide worker-process isolation and bounded
timeouts. `RuleScanner`, `RuleEngine`, and `FirewallStream` execute in the
calling process and therefore do not provide worker crash containment or a
terminate-on-timeout boundary. Review the rule-specific sections below before
enabling a policy, and reject rather than forward content when inspection is
unavailable.

## Installation and quick start

LLM FFW requires Python 3.14.7 or a newer Python 3.14 patch release. Its base
installation has no runtime dependencies outside the Python standard library.
The distribution includes a PEP 561 `py.typed` marker, so type checkers such as
mypy and Pyright consume the library's inline annotations.

The command below installs the latest published release. Documentation on the
`master` branch also covers entries under `Unreleased` in the changelog; use the
matching Git tag when documentation must describe an installed version exactly.
Examples using an `Unreleased` API require the source checkout until the next
package release.

```console
python -m pip install llm-ffw==0.17.0
```

Create one facade during application startup and reuse it for every request:

```python
from llm_ffw import Firewall

def main() -> None:
    with Firewall() as firewall:
        safe_prompt = firewall.sanitize_input(prompt)
        model_output = call_model(safe_prompt)
        safe_output = firewall.sanitize_output(model_output)

if __name__ == "__main__":
    main()
```

The entry-point guard is required because the facade uses worker processes.
Long-lived services should call `start()` and `close()` from their lifecycle
hooks instead of constructing a facade per request.
See the complete, provider-neutral
[model I/O hook example](EXAMPLES.md#reusable-model-io-hook).

## Common recipes

Use the privacy preset when email, IP, MAC, IBAN, and phone values must not leave the
application in prompts:

```python
from llm_ffw import Firewall, FirewallConfig

def main() -> None:
    text = "Contact alex@example.com from +999000000000001 at 192.0.2.10."
    with Firewall.from_config(FirewallConfig.privacy_input()) as firewall:
        safe_text = firewall.sanitize_input(text)
    assert safe_text == "Contact [REDACTED] from [REDACTED] at [REDACTED]."

if __name__ == "__main__":
    main()
```

Use `RuleScanner` when the host needs findings but will make its own enforcement
decision; findings contain safe metadata, so do not recover matched text from
their spans:

```python
from llm_ffw import RuleScanner, ScanScope

synthetic = "sk-" + "A" * 20
findings = RuleScanner().scan(synthetic, scope=ScanScope.INPUT)
assert [finding.rule_id for finding in findings] == ["secrets.detected"]
assert findings[0].redacted_preview == "[REDACTED:openai_api_key]"
```

Use the JSON API preset when model output must be valid JSON and URLs need
structural inspection:

```python
from llm_ffw import ContentBlockedError, Firewall, FirewallConfig

def main() -> None:
    with Firewall.from_config(FirewallConfig.json_api()) as firewall:
        try:
            firewall.sanitize_output('{"score": NaN}')
        except ContentBlockedError as exc:
            assert exc.findings[0].rule_id == "output.json.validity"
        else:
            raise AssertionError("invalid JSON was not blocked")

if __name__ == "__main__":
    main()
```

See the
[complete runnable examples](https://github.com/wyezee/llm-ffw/blob/master/EXAMPLES.md)
for the synchronous and async facades, lower-level APIs, streaming, catalog
reloads, and direct process-pool orchestration.

## Measured performance

The table is the publication-grade benchmark of the `0.13.0` six-rule default
and 16-rule all-text configurations at commit `4f5941a`. Tests ran on
GitHub-hosted Ubuntu and Windows runners with Python 3.14.7. Each request
contains 8,000,000 synthetic ASCII characters (about 7.63 MiB), representative
of a million-token-scale prompt. This is a size comparison rather than an exact
token count: tokenization varies by model, tokenizer, language, and content.

| Rules and payload | Ubuntu req/s / MiB/s / p95 | Windows req/s / MiB/s / p95 |
| --- | ---: | ---: |
| Default 6, clean input | 3.184 / 24.292 / 9.82 s | 5.113 / 39.009 / 6.25 s |
| Default 6, valid JSON output | 3.427 / 26.144 / 9.26 s | 5.435 / 41.469 / 5.85 s |
| All 16, clean input | 1.396 / 10.651 / 22.38 s | 2.065 / 15.756 / 15.47 s |
| All 16, valid JSON output | 0.964 / 7.353 / 32.69 s | 1.466 / 11.184 / 21.80 s |

Each row uses four workers, eight concurrent callers, and 32 requests per
round for three rounds: 96 measured requests per row and 384 per operating
system. Throughput is the median of the three rounds. The pooled end-to-end
p95 includes caller queueing from submitting 32 requests to eight caller
slots; it is not single-request service time. All 768 measured requests across
both operating systems completed with exact expected findings and no rejection,
timeout, or failure. Per-row maximum process-tree RSS ranged from 300 to
609 MiB.

These are reproducible CI measurements, not universal latency guarantees;
performance varies with input, enabled rules, policy, CPU, and concurrency.
See the [exact publication run](https://github.com/wyezee/llm-ffw/actions/runs/32234500783)
and the commands under [Development and validation](#development-and-validation).

### Capacity starting point

Benchmark the exact payload distribution and enabled rules that production will
use. As an initial estimate, divide the required aggregate MiB/s by measured
per-worker MiB/s and round up, then verify the result under the intended caller
concurrency; process scaling is not perfectly linear. Start `max_in_flight` at
one to two requests per worker so overload stays bounded, and increase it only
when measured queueing and memory remain acceptable. Set the request timeout
above measured service latency, not pooled latency that already includes caller
queueing.

Reserve memory for the parent process, every active worker, payload copies, and
operating-system variation. `FirewallManager.reload()` briefly runs old and new
worker generations together, so a reload-capable service needs enough headroom
for both generations. Treat the table as a reproducible baseline, then use the
included all-rules, concurrency, memory, and soak harnesses for deployment
sizing.

## Usage

Choose the highest-level API that fits the integration:

| API | Use it for |
| --- | --- |
| `Firewall` | Recommended production input/output sanitization and lifecycle |
| `AsyncFirewall` | The same production contract for asyncio applications |
| `FirewallManager` | The same facade with zero-downtime secret-catalog reloads |
| `AsyncFirewallManager` | Asyncio sanitization plus asynchronous catalog lifecycle |
| `FirewallStream` | Chunked input with explicit incremental or buffered enforcement |
| `RuleEngine` | Same-process scanning plus policy application |
| `RuleScanner` | Same-process detection when the host applies findings itself |
| `ProcessScannerPool` | Advanced process orchestration and explicit overload control |
| `ToolCallRule` | Provider-neutral allowlist and typed argument validation before tool execution |
| `ToolResultRule` | Provider-neutral linkage and bounded-content validation before model consumption |

Production integrations should normally begin with the `Firewall` quick
start above. The remaining APIs expose async lifecycle, streaming, hot reload,
or lower-level control when those capabilities are specifically required.

### Concurrency and object sharing

The request methods on synchronous `Firewall` and `FirewallManager` instances
are thread-safe for concurrent callers while the instance is running. Create
one per application process and share it across request threads. Their request
paths and the underlying `ProcessScannerPool` use bounded admission. Coordinate
lifecycle transitions with the service lifecycle: a request racing with close,
terminate, or a broken worker can safely receive `FirewallUnavailableError`.

Create one `AsyncFirewall` or `AsyncFirewallManager` per application process and
event loop. A single instance supports concurrent tasks on that loop, but it is
not a cross-thread or cross-event-loop request object. `FirewallStream` is
stateful and belongs to exactly one request. Never share a stream between
callers.

### Unified streaming

`FirewallStream` accepts chunked text without changing the meaning of the
configured scanner or policy. The default `AUTO` mode emits incrementally only
when every active rule and effective action can safely do so; otherwise it
buffers the request and applies the normal firewall at `finish()`:

```python
from llm_ffw import RuleEngine

engine = RuleEngine()
stream = engine.stream()
try:
    for chunk in incoming_chunks:
        safe_chunk = stream.feed(chunk)
        if safe_chunk:
            forward(safe_chunk)
    final_chunk = stream.finish()
    if final_chunk:
        forward(final_chunk)
except BaseException:
    stream.cancel()
    raise
```

With the default scanner, `execution_mode` is `StreamMode.BUFFERED` because
several baseline rules require complete-document execution in this release.
This preserves all configured protection instead of silently skipping rules.
`feed()` therefore returns an empty string and `finish()` returns the complete
sanitized result. A blocking policy raises `ContentBlockedError` from
`finish()` without returning the original text.

Applications that require early output can request it explicitly. Construction
fails with `IncrementalStreamingUnavailableError` if any active rule, catalog
shape, or policy action cannot preserve semantics:

```python
from llm_ffw import RuleEngine, RuleScanner, StreamMode
from llm_ffw.rules import PaymentCardRule, SecretsRule

engine = RuleEngine(
    scanner=RuleScanner(rules=(SecretsRule(), PaymentCardRule()))
)
stream = engine.stream(mode=StreamMode.INCREMENTAL)
```

The current release has fused incremental implementations for `SecretsRule`
and `PaymentCardRule`. Other active rules are reported as
`StreamingSupport.END_OF_STREAM` and cause `AUTO` to buffer or `INCREMENTAL` to
reject. This is a capability boundary, not a security downgrade; more rules can
gain incremental implementations behind the same API without changing client
integration. Inspect `execution_mode` and `rule_capabilities` before accepting
traffic when deployment behavior depends on early emission.
`StreamMode.BUFFERED` can be selected to require full batch semantics
explicitly.

Incremental execution requires an effective `REDACT` action because previously
emitted text cannot be recalled. Payment-card inspection emits behind a bounded
watermark so candidates split across chunks have exactly the same result as a
batch scan. Candidate shapes that would need attacker-sized retention fall
back to buffered execution in `AUTO` mode. Findings retain spans into the
original concatenated text and disclosure-safe metadata. Each stream belongs
to one request and must not be shared between concurrent callers.
Streaming is an in-process `RuleEngine` API: it does not provide the worker
process isolation, crash containment, or terminate-on-timeout enforcement of
the production facades.

### Async usage

Asyncio applications should use `AsyncFirewall` directly instead of wrapping
the synchronous facade with `asyncio.to_thread()`:

```python
from llm_ffw import AsyncFirewall

async def handle_request(firewall: AsyncFirewall, prompt: str) -> str:
    safe_prompt = await firewall.sanitize_input(prompt)
    model_output = await call_model_async(safe_prompt)
    return await firewall.sanitize_output(
        model_output,
        prompt_context=safe_prompt,
    )

async def main(prompt: str) -> None:
    async with AsyncFirewall() as firewall:
        response = await handle_request(firewall, prompt)
```

In a service, create and start one async facade during application startup,
reuse it for requests, and await `close()` during shutdown. It supports async
`start()`, `close()`, `terminate()`, `kill()`, input/output sanitization, and
structured-result methods. `capabilities()` and `state` remain synchronous
because they return in-memory metadata without blocking.

The async facade uses the same process scanner, policies, configuration,
timeouts, and exceptions as `Firewall`. Its private request executor and
async admission gate are both bounded by `ProcessScannerPoolConfig`; it never
blocks the event loop while waiting for CPU workers. One instance belongs to
one event loop for request processing; an idle instance can still be closed
from a replacement shutdown loop. Canceling an await does not abandon its running scan: the scan
finishes under the configured request timeout and retains its capacity slot
until completion, preventing cancellation-driven queue growth. Lifecycle
cleanup also finishes before cancellation propagates, even when cleanup itself
fails, so worker executors are not leaked.

### FastAPI lifespan integration

FastAPI applications should create one `AsyncFirewall` inside the application's
lifespan and reuse it for every request handled by that worker. FastAPI itself
remains an optional host dependency and is not installed by `llm-ffw`:

```python
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Body, FastAPI, HTTPException, Request
from llm_ffw import (
    AsyncFirewall,
    ContentBlockedError,
    FirewallUnavailableError,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    firewall = AsyncFirewall()
    try:
        await firewall.start()
        app.state.firewall = firewall
        yield
    finally:
        await firewall.close()


app = FastAPI(lifespan=lifespan)


@app.post("/sanitize")
async def sanitize(
    request: Request,
    prompt: Annotated[str, Body(embed=True)],
) -> dict[str, str]:
    firewall: AsyncFirewall = request.app.state.firewall
    try:
        return {"text": await firewall.sanitize_input(prompt)}
    except ContentBlockedError:
        raise HTTPException(status_code=422, detail="content blocked") from None
    except FirewallUnavailableError:
        raise HTTPException(
            status_code=503,
            detail="inspection unavailable",
        ) from None
```

With multiple ASGI server workers, each worker process runs its own lifespan and
owns its own firewall worker pool. Include those nested processes in CPU and
memory sizing. The prompt is a JSON request-body field rather than a query
parameter so access logs do not normally capture it; configure an upstream body
size limit no greater than the firewall's input limit so oversized bodies are
rejected before application parsing. FastAPI recommends the lifespan
async-context-manager pattern for startup and shutdown; see its
[official lifespan documentation](https://fastapi.tiangolo.com/advanced/events/).

### Results and failure handling

`ContentBlockedError` represents a configured block decision.
`FirewallUnavailableError` safely combines saturation, timeout, lifecycle, and
worker failures without retaining the submitted text or an internal exception
chain. Hosts should reject rather than forward content when inspection is
unavailable.

Applications that need safe audit metadata can request a structured result
without dropping to the process-pool API:

```python
result = firewall.sanitize_input_result(prompt)
safe_prompt = result.text
for finding in result.findings:
    record_metric(finding.rule_id, finding.action.value)
```

`sanitize_output_result()` provides the same contract for model output. These
methods still raise `ContentBlockedError` and `FirewallUnavailableError`, so a
returned result is always forwardable under the selected policy. It retains
only policy-processed text rather than a second pre-inspection copy; an explicit
audit policy can intentionally leave that text unchanged. Its representation
always omits the text as an additional safeguard. Do not log `result.text` or
recover matched content by slicing the original request with finding spans.

`SanitizationResult` contains the following stable fields:

| Field | Meaning |
| --- | --- |
| `text` | Policy-processed text that is safe to forward; excluded from `repr()` |
| `policy_id`, `policy_version` | Identity of the policy that made the decision |
| `scope` | `ScanScope.INPUT` or `ScanScope.OUTPUT` |
| `decision` | Strongest effective `Action` across the findings |
| `findings` | Immutable tuple of disclosure-safe `Finding` objects |

Each finding contains `rule_id`, `severity`, `action`, a half-open original-text
`span`, a safe `message`, an optional category-only `redacted_preview`, and
string-only `metadata`. `finding.to_dict()` returns the same information in a
JSON-compatible form without the matched value.

Handle both failure modes explicitly and fail closed when inspection is
unavailable:

```python
from llm_ffw import ContentBlockedError, FirewallUnavailableError

try:
    safe_prompt = firewall.sanitize_input(prompt)
except ContentBlockedError as exc:
    record_block(exc.policy_id, exc.scope, exc.findings)
    reject_request()
except FirewallUnavailableError as exc:
    record_unavailable(exc.cause_type)
    reject_request()
```

`ContentBlockedError` exposes policy identity, scope, and safe findings but not
the submitted text. `FirewallUnavailableError.cause_type` is a bounded category
such as `TimeoutError` or `ProcessPoolSaturatedError`; the original exception
and submitted text are not retained.

`RuleEngine`, `ProcessScannerPool`, and `RuleScanner` are lower-level APIs for
custom policy results, process orchestration, and detection-only evaluation.

```python
from llm_ffw import RuleScanner, ScanScope

scanner = RuleScanner()
text = get_llm_input()  # Your application supplies the text.

findings = scanner.scan(text, scope=ScanScope.INPUT)
for finding in findings:
    print(finding.rule_id, finding.severity.value, finding.span)

safe_text = scanner.redact(text, findings)
```

Output rules use the same scanner with an explicit direction. Paired output
rules can opt into normalized prompt context; rules that do not request it pay
no normalization cost:

```python
findings = scanner.scan(
    model_output,
    scope=ScanScope.OUTPUT,
    prompt_context=prompt,
)
```

Omitting `scope` preserves the input-scan default. The text and optional prompt
context are each bounded by `RuleScannerConfig.max_input_chars`.

Do not log `text` or slice a finding's span for diagnostics. Findings contain a
category-only `redacted_preview` suitable for reporting.

The default `RuleScannerConfig.max_input_chars` is 8,000,000 characters, providing
headroom for a typical one-million-token text context. Token-to-character ratios
vary by model, language, and content; callers should still set an explicit limit
appropriate to their deployment and memory budget.

## Facade configuration

`Firewall` and `AsyncFirewall` accept the same immutable startup
configuration. Create and validate one facade, then reuse it rather than
rebuilding it per request.

For common deployments, use one immutable `FirewallConfig` preset instead of a
long constructor. Preset names describe their actual behavior; none claims to
be universally "secure" or "enterprise":

```python
from dataclasses import replace
from llm_ffw import FirewallConfig, Firewall

config = replace(
    FirewallConfig.privacy_input(),
    request_timeout_seconds=10.0,
)

with Firewall.from_config(config) as firewall:
    safe_prompt = firewall.sanitize_input(prompt)
```

`default()` selects the seven-rule baseline, `privacy_input()` additionally
enables conservative IP, MAC, IBAN, email, and phone input rules, and `json_api()`
adds strict JSON-output and unsafe-URL inspection. `all_text_rules()` enables
all 20 text rules, requires an explicit deployment-owned
`BannedSubstringCatalog`, and uses a 30-second request timeout suitable for
initial large-payload testing. Deployments must still tune that deadline from
their own payload and latency measurements. Direct constructor parameters
remain available for precise configuration, and `from_config()` is supported
by synchronous and asynchronous facades and managers.

| Constructor parameter | Purpose |
| --- | --- |
| `scanner_config` | Input limit, redaction marker, and default-rule enable flags |
| `pool_config` | Worker count, bounded in-flight capacity, recycling, and admission timeout |
| `additional_secret_catalog` | Add organization signatures while retaining all built-ins |
| `replacement_secret_catalog` | Deliberately replace the complete built-in secret catalog |
| `banned_substring_catalog` | Enable a deployment-owned immutable literal catalog |
| `json_output_config` | Enable bounded output-only JSON validation |
| `unsafe_url_config` | Enable bounded input/output URL inspection |
| `external_resource_config` | Enable bounded output image-resource inspection |
| `ip_address_config` | Enable bounded canonical IP-address inspection |
| `mac_address_config` | Enable bounded canonical 48-bit MAC-address inspection |
| `iban_config` | Enable registered-length and MOD-97 IBAN inspection |
| `authorization_header_config` | Enable bounded Basic/Bearer Authorization-header inspection |
| `connection_string_config` | Enable bounded URI and ADO/ODBC connection-string credential inspection |
| `credential_assignment_config` | Enable bounded credential assignment inspection with optional exact field-name extensions |
| `email_address_config` | Enable bounded conservative email inspection |
| `phone_number_config` | Enable bounded conservative E.164-style phone inspection |
| `payment_card_config` | Customize enabled payment-card limits and scopes |
| `private_key_config` | Customize enabled private-key limits and scopes |
| `jwt_token_config` | Customize enabled JWT limits and scopes |
| `repetition_config` | Enable conservative exact character, token, and line repetition inspection |
| `policy` | Select balanced, strict, audit, or a versioned custom policy |
| `request_timeout_seconds` | Positive per-request facade deadline; defaults to 30 seconds |

The two secret-catalog parameters are mutually exclusive. Passing `None` for
the opt-in banned-substring, JSON, unsafe-URL, external-resource, IP-address, MAC-address, IBAN,
Authorization-header, connection-string, credential-assignment, email-address, phone-number, and repetition configurations leaves each corresponding
rule disabled. Payment-card,
private-key, JWT, invisible-character, Unicode tag, and bidi-control rules are
enabled by `RuleScannerConfig`
defaults; their dedicated config objects customize bounds and scopes rather
than enabling them.

`ProcessScannerPoolConfig` controls `max_workers`, `max_in_flight`,
`max_tasks_per_child`, and `admission_timeout_seconds`. Size these from measured
deployment load and memory rather than constructing an unbounded queue.

### Policies

The default `BALANCED_POLICY` preserves flow by redacting or removing content
where safe and blocks invalid JSON or unsafe malformed private-key cases.
`STRICT_POLICY` increases blocking for security findings. `AUDIT_POLICY` changes
findings to `REVIEW` and returns the original text, so use it only when another
trusted enforcement layer consumes the findings.

Select a complete built-in policy directly, for example
`Firewall(policy=STRICT_POLICY)`. Use a custom policy only when a deployment
needs an explicit rule-and-scope exception:

```python
from llm_ffw import (
    Action,
    FirewallPolicy,
    Firewall,
    PolicyOverride,
    ScanScope,
    UnsafeURLConfig,
)

policy = FirewallPolicy(
    policy_id="acme.production",
    version="1.0.0",
    overrides=(
        PolicyOverride(
            rule_id="url.unsafe",
            scope=ScanScope.OUTPUT,
            action=Action.BLOCK,
        ),
    ),
)
firewall = Firewall(
    unsafe_url_config=UnsafeURLConfig(),
    policy=policy,
)
```

An override is exact to one stable `rule_id` and scope. Findings without an
override retain the rule's recommended action. Duplicate overrides fail when
the policy is constructed; unknown overrides fail when a firewall validates the
policy. JSON validity can only be configured as `BLOCK` or `REVIEW` because
malformed JSON cannot be safely redacted into valid output.

## Rule configuration

The table shows enabled state and effective behavior under the balanced policy.
Strict and audit policies can change the effective action.

| Rule ID | Default | Scope | Balanced behavior | Configuration |
| --- | --- | --- | --- | --- |
| `secrets.detected` | Enabled | Input/output | Redact | Secret catalog |
| `unicode.invisible_characters` | Enabled | Input | Remove; block bounded overflow | `RuleScannerConfig` |
| `unicode.tag_smuggling` | Enabled | Input | Remove; block bounded overflow | `RuleScannerConfig` |
| `unicode.bidi_controls` | Enabled | Input/output | Remove overrides; review other explicit controls; block bounded overflow | `RuleScannerConfig` |
| `pii.payment_card` | Enabled | Input/output | Redact | `PaymentCardConfig` |
| `secrets.private_key` | Enabled | Input/output | Redact complete blocks; block unsafe malformed cases | `PrivateKeyConfig` |
| `secrets.jwt_token` | Enabled | Input/output | Redact | `JWTTokenConfig` |
| `content.banned_substrings` | Opt-in | Catalog-defined | Pattern action; redact by default | `BannedSubstringCatalog` |
| `output.json.validity` | Opt-in | Output | Block | `JSONOutputConfig` |
| `url.unsafe` | Opt-in | Input/output by default | Redact | `UnsafeURLConfig` |
| `output.external_resource` | Opt-in | Output | Redact | `ExternalResourceConfig` |
| `pii.ip_address` | Opt-in | Input by default | Redact | `IPAddressConfig` |
| `pii.mac_address` | Opt-in | Input by default | Redact | `MACAddressConfig` |
| `pii.iban` | Opt-in | Input by default | Redact | `IBANConfig` |
| `secrets.authorization_header` | Opt-in | Input/output | Redact | `AuthorizationHeaderConfig` |
| `secrets.connection_string` | Opt-in | Input/output | Redact | `ConnectionStringConfig` |
| `secrets.credential_assignment` | Opt-in | Input/output | Redact | `CredentialAssignmentConfig` |
| `pii.email_address` | Opt-in | Input by default | Redact | `EmailAddressConfig` |
| `pii.phone_number` | Opt-in | Input by default | Redact | `PhoneNumberConfig` |
| `text.excessive_repetition` | Opt-in | Input/output | Review | `RepetitionConfig` |
| `tools.call.validity` | Opt-in | Tool call | Block | `ToolDefinition`, `ToolCallConfig` |
| `tools.result.validity` | Opt-in | Tool result | Block | `ToolResultConfig` |

### Opt-in tool-call validation

Applications that execute model-selected tools can declare the callable tools
and a bounded JSON-Schema subset once at startup. Validate the provider's
decoded tool call immediately before dispatch:

```python
from llm_ffw import ToolCall, ToolCallRule, ToolDefinition

tool_calls = ToolCallRule(
    (
        ToolDefinition(
            name="get_weather",
            parameters={
                "type": "object",
                "properties": {
                    "city": {"type": "string"},
                    "units": {
                        "type": "string",
                        "enum": ["celsius", "fahrenheit"],
                    },
                },
                "required": ["city"],
                "additionalProperties": False,
            },
        ),
    )
)

call = tool_calls.build_call(
    "get_weather",
    {"city": "Pune", "units": "celsius"},
)
safe_call = tool_calls.enforce(call)
dispatch(safe_call.name, safe_call.arguments)
```

`ToolCallRule` blocks undeclared tools, arguments supplied to no-argument
tools, type and enum mismatches, missing required properties, forbidden extra
properties, configured resource-limit violations, and text-rule findings in
argument keys or string values. Structured arguments are treated as outbound
text. Its supported schema
keywords are `type`, `properties`, `required`, `additionalProperties`, `items`,
and scalar `enum`; each schema node must declare one of `object`, `array`,
`string`, `number`, `integer`, `boolean`, or `null`. Regex, references,
combinators, coercion, and defaults are deliberately unsupported. Every object
node must explicitly set boolean `additionalProperties`; use `false` for the
safe closed-object contract or deliberately choose `true` for an open object.

`build_call()` copies decoded built-in JSON values into an immutable tree under
the rule's configured limits before validation. Direct `ToolCall` construction
uses the same production defaults and accepts a trusted `limits=` override.
`ToolCall`
and excludes arguments and call IDs from `repr()`. The rule declares
`ScanScope.TOOL_CALL`. A rejected call produces one disclosure-safe `Finding`
with a structured zero-width span and no tool name, argument key, or argument
value taken from untrusted input. Construct `ToolCallRule` once and reuse it;
schema compilation does not
occur on the request path. `enforce()` returns the same safe call or raises
`ToolCallBlockedError`; `validate()` is available when the host wants the
finding tuple without raising.

### Opt-in tool-result validation

Validate tool results as one bounded request batch before adding them to model
context. Batch validation is necessary because result IDs must be linked to
expected calls and unique within the request:

```python
from llm_ffw import (
    ToolCall,
    ToolResult,
    ToolResultBatch,
    ToolResultRule,
)

expected = ToolCall(
    "get_weather",
    {"city": "Pune"},
    call_id="call-1",
)
tool_results = ToolResultRule()
returned = tool_results.build_result(
    call_id="call-1",
    name="get_weather",
    content="Sunny, 28 C",
)
safe_batch = tool_results.enforce(
    tool_results.build_batch((expected,), (returned,))
)
add_tool_results_to_context(safe_batch.results)
```

`ToolResultRule` blocks missing or duplicate expected call IDs; missing,
duplicate, or unmatched result IDs; missing or mismatched tool names; and
configured batch or content resource-limit violations. A batch may contain
results for a subset of the expected calls, but every included result must
link exactly once. It does
not claim that a tool actually ran or that returned content is truthful.

Content inspection is enabled by default. It uses the deterministic scanner
baseline, treats tool calls as outbound text and tool results as inbound text,
and translates the first text finding into one disclosure-safe structured
BLOCK finding. A trusted host can inject a narrower `RuleScanner`; setting
`inspect_content=False` explicitly disables this layer.

Result content must be either a string or a list/tuple of JSON object blocks.
This provider-neutral shape can carry simple text or multimodal references
without accepting provider code. `build_result()` and `build_batch()` apply one
configuration while copying values and enforcing aggregate batch budgets.
Direct constructors use the same defaults and accept a trusted `limits=`
override. Values are copied into bounded immutable trees, and result IDs,
names, content, and complete batches are excluded from
`repr()`. The rule declares `ScanScope.TOOL_RESULT`; rejection produces one
structured zero-width finding without dynamic IDs, names, keys, or values.
`enforce()` raises `ToolResultBlockedError`, while `validate()` returns the
finding tuple for hosts that apply enforcement themselves.

### Default invisible-character canonicalization

`InvisibleCharactersRule` removes runs of U+200B zero-width space, U+200C
zero-width non-joiner, U+200D zero-width joiner, U+2060 word joiner, and U+FEFF
zero-width no-break space only when embedded between ASCII token characters.
It then rescans the cleaned input through every enabled rule. Clean ASCII
requests retain a single scan. The rule is input-only and enabled by default.
Because contextual joiners can be intentional inside source-code identifiers,
code-preserving deployments can opt out:

```python
from llm_ffw import Firewall, RuleScannerConfig

firewall = Firewall(
    scanner_config=RuleScannerConfig(enable_invisible_characters=False),
)
```

More than 64 contextual runs produces one bounded `BLOCK` recommendation.
Balanced and strict policies enforce that block; audit or a custom policy may
override it. Other format, joining, bidi, private-use, and unassigned
characters are not removed.

### Default Unicode tag canonicalization

`UnicodeTagSmugglingRule` removes invisible tag-character runs from input and
rescans the cleaned text. It preserves the three RGI subdivision-flag tag
sequences pinned by Unicode Emoji 17.0 and treats malformed, extended, or other
tag runs as findings. Applications can independently opt out with
`RuleScannerConfig(enable_unicode_tag_smuggling=False)`. More than 64 relevant runs
fails closed.

### Default bidirectional-control inspection

`BidiControlRule` inspects input and output for the nine explicit formatting
controls defined by [Unicode Standard Annex #9](https://www.unicode.org/reports/tr9/).
Balanced policy removes LRO and RLO directional overrides, then rescans the
cleaned text through every enabled rule. It reports LRE, RLE, PDF, LRI, RLI,
FSI, and PDI for review without changing the text because isolates and
embeddings can be legitimate in plain multilingual content. LRM, RLM, and ALM
are implicit directional marks and are deliberately preserved. Strict policy
blocks every finding; audit policy only reviews. Applications can opt out with
`RuleScannerConfig(enable_bidi_controls=False)`. More than 64 runs in either
control group fails closed. This follows Unicode's guidance to treat bidi
controls contextually rather than forbidding all directional formatting.

### Deployment-defined banned substrings

An optional immutable `BannedSubstringCatalog` provides constrained substring
or ASCII-word matching for input and output. It defaults to redaction and never
accepts caller regex.

```python
from llm_ffw import (
    Action,
    BannedSubstring,
    BannedSubstringCatalog,
    Firewall,
    LiteralMatchMode,
    ScanScope,
)

content_catalog = BannedSubstringCatalog(
    catalog_id="acme.output_terms",
    version="1.0.0",
    scopes=(ScanScope.OUTPUT,),
    patterns=(
        BannedSubstring(
            pattern_id="acme.internal_codename",
            value="Project Northstar",
            match_mode=LiteralMatchMode.SUBSTRING,
            case_sensitive=False,
            action=Action.REDACT,
        ),
    ),
)
firewall = Firewall(banned_substring_catalog=content_catalog)
```

Catalogs accept 1–1,024 unique literals. Each value must contain 3–64 printable
ASCII characters, and the complete catalog is bounded to 65,536 literal
characters. `SUBSTRING` matches within text; `ASCII_WORD` additionally requires
ASCII word boundaries. Matching can be case-sensitive or ASCII
case-insensitive. The host owns and versions this trusted startup configuration;
do not accept catalog definitions from ordinary request data.

### Opt-in JSON output validation

Applications that require a complete JSON response can enable the bounded,
output-only `JSONOutputRule`:

```python
from llm_ffw import JSONOutputConfig, Firewall

firewall = Firewall(json_output_config=JSONOutputConfig())
```

Malformed syntax, duplicate keys, non-standard non-finite constants, and
configured resource-limit violations block by default. The rule does not
extract JSON from Markdown or repair malformed output.

### Opt-in unsafe URL inspection

Applications that pass model-produced URLs to users or downstream tools can
enable bounded structural URL inspection:

```python
from llm_ffw import Firewall, UnsafeURLConfig

firewall = Firewall(
    unsafe_url_config=UnsafeURLConfig(
        denied_hostnames=("blocked.example",),
        denied_hostname_suffixes=("internal.example",),
        allowed_hostname_suffixes=("public.example",),
    )
)
```

`UnsafeURLRule` redacts dangerous schemes, embedded URL user-info, local or
non-public IP targets, exact documented cloud metadata hostnames, and ambiguous
authorities under balanced policy. It checks input and output by default;
deployments can restrict its `scopes`. It performs no DNS, HTTP, reputation,
model, or other network call.

Hostname policy is normalized once when configuration is constructed. Exact
fields accept DNS names or IP literals. Suffix fields accept DNS names only;
`internal.example` matches both the apex and its subdomains, but not
`notinternal.example`. Supplying either allow field enables a restrictive
allowlist. Denies and built-in unsafe-URL findings always take precedence over
allows. The four policy fields together accept at most 1,024 entries. Runtime
capabilities disclose only policy entry counts, never configured hostnames.

### Opt-in external image-resource allowlist

Applications that render model output as Markdown or HTML can inspect
auto-loaded external images before rendering:

```python
from llm_ffw import ExternalResourceConfig, Firewall

with Firewall(
    external_resource_config=ExternalResourceConfig(
        allowed_hostname_suffixes=("assets.example",),
    )
) as firewall:
    safe = firewall.sanitize_output(
        "![status](https://outside.example/pixel.png?payload=synthetic)"
    )
```

`ExternalResourceRule` is output-only and recognizes bounded inline CommonMark
image destinations and HTML `<img src>` attributes. It redacts every external
HTTP(S) URL whose host is outside the configured allowlist, regardless of the
URL's path or query shape. Scheme-relative URLs are included, malformed or
ambiguous HTTP(S) authorities fail closed, and an empty allowlist denies every
external image host. Hostname normalization and label-boundary suffix matching
are shared with `UnsafeURLRule`. Exact and suffix entries are bounded to 1,024
total, and capabilities disclose counts, never hostname values. A suffix entry
trusts its apex and every subdomain, so do not allowlist public or untrusted
multi-tenant suffixes.

The syntax boundary follows [CommonMark 0.31.2 images](https://spec.commonmark.org/0.31.2/#images)
and the HTML Standard's [`img` resource model](https://html.spec.whatwg.org/multipage/embedded-content.html#the-img-element).
This first bounded version deliberately excludes ordinary clickable links,
reference-style Markdown images, `srcset`, CSS URLs, and other media elements.
It is lexical inspection, not proof that data is secret or that a particular
renderer will fetch the resource. Keep renderer-level remote-resource blocking
as the primary control.

### Opt-in IP-address inspection

Applications that treat IP addresses as personal or infrastructure-sensitive
data can enable deterministic inspection:

```python
from llm_ffw import IPAddressConfig, Firewall, ScanScope

firewall = Firewall(
    ip_address_config=IPAddressConfig(
        scopes=(ScanScope.INPUT, ScanScope.OUTPUT),
    )
)
```

`IPAddressRule` recognizes standard IPv4 and IPv6 text using bounded candidate
discovery followed by Python's `ipaddress` parser. It is input-only unless
configured otherwise, redacts under balanced policy, and can independently
disable either address family. IPv6-shaped token runs beyond the 45-character
parser bound fail closed instead of being silently skipped. It intentionally does not normalize obfuscated
addresses or claim complete PII detection; the high-precision default targets
accidental disclosure with predictable false-positive and performance bounds.

### Opt-in MAC-address inspection

Applications that treat hardware interface identifiers as personal or
infrastructure-sensitive data can enable deterministic inspection:

```python
from llm_ffw import Firewall, MACAddressConfig, ScanScope

firewall = Firewall(
    mac_address_config=MACAddressConfig(
        scopes=(ScanScope.INPUT, ScanScope.OUTPUT),
    )
)
```

`MACAddressRule` recognizes canonical 48-bit addresses written as six
two-digit hexadecimal octets with one consistent colon or hyphen separator.
An immediately preceding case-insensitive `MAC:` label is supported without
matching MAC-shaped suffixes inside IPv6 text.
It is input-only unless configured otherwise and redacts under balanced
policy. Cisco dotted notation, mixed separators, EUI-64 values, obfuscation,
and vendor ownership lookup are intentionally outside this narrow,
high-precision rule.

### Opt-in IBAN inspection

Applications that treat bank-account identifiers as sensitive can enable
deterministic IBAN inspection:

```python
from llm_ffw import IBANConfig, Firewall, ScanScope

firewall = Firewall(
    iban_config=IBANConfig(
        scopes=(ScanScope.INPUT, ScanScope.OUTPUT),
    )
)
```

`IBANRule` recognizes ASCII case-insensitive electronic IBANs and canonical space-grouped
print forms. A candidate must use a country code and exact length pinned to
the
[SWIFT IBAN Registry Release 102 (June 2026)](https://www.swift.com/swift-resource/9606/download),
contain only the standard uppercase alphanumeric alphabet, and pass the
ISO/IEC 7064 MOD-97-10 check. It is input-only unless configured otherwise and
redacts under balanced policy.

The checksum and registered length make this substantially narrower than a
generic account-number regex, but they do not prove that an account exists,
is active, or belongs to anyone. The rule does not validate country-specific
BBAN subfields or domestic check digits, repair obfuscation, accept lowercase,
or make any network call. Registry release and issue date are exposed through
capabilities and finding metadata so deployments can audit the pinned data.

### Opt-in Authorization-header inspection

Applications that may pass HTTP request dumps, logs, or generated client code
through a model can redact Basic and Bearer credentials while preserving the
header structure:

```python
from llm_ffw import AuthorizationHeaderConfig, Firewall

firewall = Firewall(
    authorization_header_config=AuthorizationHeaderConfig(),
)
```

`AuthorizationHeaderRule` recognizes three explicit, case-insensitive shapes:
optionally indented `Authorization:` headers at the start of a normalized line;
a line-start `curl -H` or `curl --header` command whose immediately following
header is single- or double-quoted; and a double-quoted `Authorization` field at
an object-style `{` or `,` JSON boundary. The field name must be followed by the
syntax-appropriate colon. Bearer values use the token68 alphabet with any
padding confined to the end. Basic values must be canonical base64, decode
successfully, and contain the required username/password colon. Only the
credential span is redacted; surrounding header, command, and JSON structure
remain.

The rule is opt-in, scans input and output by default, and has hard bounds on
candidate count and credential length. It deliberately excludes Digest,
`Proxy-Authorization`, authentication parameters, header folding, inline prose,
unquoted curl header arguments, curl options before `-H`/`--header`, and
placeholder syntax such as `<token>`. Non-placeholder values are redacted even
when malformed, because an unambiguous credential shape must not fail open.
Syntactic validity does not prove
that a credential is active or accepted by any server, and the rule makes no
network call.

### Opt-in connection-string inspection

Applications that send configuration, logs, or generated deployment material
through a model can redact embedded database and message-broker credentials:

```python
from llm_ffw import ConnectionStringConfig, Firewall

firewall = Firewall(
    connection_string_config=ConnectionStringConfig(),
)
```

`ConnectionStringRule` recognizes credentials in source-backed URI forms for
AMQP, MongoDB, PostgreSQL, Redis, and SQL Server schemes. It also
recognizes semicolon-delimited ADO/ODBC `Password=` or `Pwd=` fields when a
nearby `Server=` or `Data Source=` field establishes connection-string context.
URI passwords may be percent-encoded; keyword values may be unquoted,
double-quoted, or ODBC brace-escaped. Only the credential value is redacted, so
the surrounding connection-string structure remains usable for diagnosis.

The rule is opt-in, scans both directions by default, ignores explicit password
placeholders, and bounds candidate count, credential length, and keyword-context
distance. It deliberately excludes generic URLs, password assignments without
connection context, JDBC subprotocols, and unreviewed vendor-specific aliases.
Malformed percent encoding or unterminated quoted values in an otherwise
unambiguous connection string are redacted rather than allowed through. Syntax
does not prove that a credential is active, and the rule performs no network
or database calls.

The supported forms are pinned to the vendor specifications for
[RabbitMQ AMQP URIs](https://www.rabbitmq.com/docs/4.1/uri-spec),
[MongoDB connection strings](https://www.mongodb.com/docs/manual/reference/connection-string-formats/),
[PostgreSQL connection URIs](https://www.postgresql.org/docs/16/libpq-connect.html),
[Redis URIs](https://redis.io/docs/latest/develop/tools/cli/),
[SQL Server connection strings](https://learn.microsoft.com/en-us/sql/connect/golang/connection-strings),
and [MySQL keyword connection strings](https://dev.mysql.com/doc/connector-net/en/connector-net-connections-string.html).

### Opt-in credential-assignment inspection

Applications that send environment files, deployment configuration, generated
code, or logs through a model can redact assigned credentials while preserving
the field name and surrounding structure:

```python
from llm_ffw import CredentialAssignmentConfig, Firewall

firewall = Firewall(
    credential_assignment_config=CredentialAssignmentConfig(
        additional_keywords=("tenant_signing_credential",),
    )
)

safe = firewall.sanitize_input(
    "tenant_signing_credential=synthetic-example-value-123"
)
```

`CredentialAssignmentRule` recognizes line-start env, shell `export`, and
YAML-like assignments plus quoted fields at object boundaries. Built-in
high-confidence names include password, API-key, access-token, refresh-token,
client-secret, private-token, and AWS secret-access-key forms; compound names
such as `DB_PASSWORD` are recognized by a bounded suffix rule. Values shorter
than four characters and explicit placeholders are ignored. Quoted and
unquoted values are supported, and only the value span is redacted.

The immutable configuration accepts at most 256 additional lowercase ASCII
field names. Extensions are exact after normalizing `.`, `-`, and `_`
separators; they are not regexes and do not create suffix matches. Candidate
count and value length are bounded and fail closed. Findings and capabilities
report only safe counts and syntax categories—never field names or assigned
values. This rule detects assignment syntax; it does not determine whether a
credential is active.

### Opt-in email-address inspection

Applications that treat email addresses as personal data can enable bounded,
deterministic inspection:

```python
from llm_ffw import EmailAddressConfig, Firewall, ScanScope

firewall = Firewall(
    email_address_config=EmailAddressConfig(
        scopes=(ScanScope.INPUT, ScanScope.OUTPUT),
    )
)
```

`EmailAddressRule` recognizes a conservative ASCII mailbox subset with
DNS-style domains and common dot, underscore, percent, plus, and hyphen local
parts. It requires at least one domain dot, enforces standard local-part,
label, domain, and total-length bounds, uses ASCII identifier boundaries, and
redacts under balanced policy. Leading sentence punctuation is excluded from
the exact finding span. It
does not attempt RFC-complete quoted local parts, comments, address literals,
Unicode mailbox syntax, DNS ownership checks, or obfuscation repair. These
limits deliberately favor predictable high-precision privacy protection.

### Opt-in phone-number inspection

Applications that treat global phone numbers as personal data can enable
bounded, deterministic inspection:

```python
from llm_ffw import Firewall, PhoneNumberConfig, ScanScope

firewall = Firewall(
    phone_number_config=PhoneNumberConfig(
        scopes=(ScanScope.INPUT, ScanScope.OUTPUT),
    )
)
```

`PhoneNumberRule` recognizes a conservative E.164-style subset: `+`, followed
by 7–15 ASCII digits, with a nonzero first digit and no separators or extension.
The 15-digit ceiling comes from ITU-T E.164; the 7-digit floor is a product
heuristic that reduces collisions with short numeric identifiers. ASCII
identifier boundaries prevent matches embedded in larger identifiers, and
formatted numbers such as `+44 20 7946 0958` are deliberately excluded rather
than partially redacted. The rule defaults to input-only redaction and can be
enabled for output through `scopes`.

This is syntax-and-length detection, not proof that a country code, subscriber
number, or assignment is valid. It does not normalize local numbers, formatted
numbers, extensions, vanity numbers, or Unicode digits. See
[ITU-T E.164](https://www.itu.int/rec/T-REC-E.164/en) and
[RFC 3966](https://www.rfc-editor.org/rfc/rfc3966.html) for the broader
standards.

### Opt-in excessive-repetition inspection

Applications that want a deterministic signal for degenerate prompts or model
outputs can enable exact repetition inspection:

```python
from llm_ffw import Firewall, RepetitionConfig

firewall = Firewall(repetition_config=RepetitionConfig())
```

`RepetitionRule` reports non-whitespace character runs of 256 characters,
identical whitespace-delimited tokens repeated 64 times, and identical non-empty
lines repeated 32 times by default. It scans input and output, returns `REVIEW`,
and treats every separator recognized by Python's `str.splitlines()`
consistently, switching to bounded streaming inspection for separator-dense
input. It never labels content as semantic "gibberish." Punctuation-only token runs,
blank lines, tokens longer than 128 characters, and lines longer than 4,096
characters are deliberately excluded to keep the signal conservative and memory
bounded. Thresholds and the finding limit are immutable startup configuration;
capabilities expose their effective values.

### Default payment-card inspection

Bounded Luhn-based payment-card inspection is enabled in both directions by
default. Applications can customize its limits and scopes:

```python
from llm_ffw import Firewall, PaymentCardConfig

firewall = Firewall(payment_card_config=PaymentCardConfig())
```

`PaymentCardRule` redacts structurally plausible 13–19 digit ASCII candidates
under balanced policy. Luhn is a checksum, not proof that a card exists or is
active. Applications that intentionally pass checksum-valid identifiers or test
cards can opt out with `RuleScannerConfig(enable_payment_cards=False)`.

### Supported secret signatures

Armored private-key inspection is independently enabled by default for input
and output. Balanced policy redacts complete blocks and safely contains
malformed or oversized blocks. Applications can customize bounded limits with
`PrivateKeyConfig` or explicitly opt out with
`RuleScannerConfig(enable_private_keys=False)`.

Compact JWT inspection is also enabled by default. It validates canonical
Base64URL, unique-member JSON header/payload objects, algorithm/signature
consistency, and JWT-specific type or registered-claim evidence before
redaction. It does not verify signatures or trust claims. Applications can
customize bounded limits with `JWTTokenConfig` or opt out with
`RuleScannerConfig(enable_jwt_tokens=False)`.

Built-in catalog `3.0.0` has 28 constrained signatures and 47 prefixes for
OpenAI, GitHub, AWS, Anthropic, GitLab, Slack, Stripe, Hugging Face, Google,
npm, PyPI, SendGrid, and Shopify.

Credential-shaped values are high-severity `redact` findings. Credential
identifiers such as Twilio `SK...` API key SIDs are deliberately excluded
because they cannot authenticate without a separate secret.

The rule does not attempt generic password or entropy detection.

## Versioned signature catalogs

`SecretsRule` uses `BUILTIN_SECRET_CATALOG` by default. Applications can pin an
in-memory `SecretCatalog` containing organization-specific signatures. Catalogs
contain literal prefixes, ASCII character sets, and length bounds; they cannot
contain executable callbacks or arbitrary regular expressions.

```python
import string

from llm_ffw import Firewall, SecretCatalog, SecretSignature

internal = SecretSignature(
    signature_id="acme.service_token",
    provider="acme",
    secret_type="service_token",
    prefixes=("acme_live_",),
    suffix_chars=string.ascii_letters + string.digits,
    min_suffix_chars=32,
    max_suffix_chars=32,
    boundary_chars=string.ascii_letters + string.digits + "_",
    source="internal://security/service-token-format",
)
additional_catalog = SecretCatalog(
    # This coordinate identifies the final built-ins-plus-Acme catalog.
    catalog_id="acme.secrets.with_llm_ffw_builtins",
    version="3.0.0+acme.1",
    signatures=(internal,),
)
firewall = Firewall(additional_secret_catalog=additional_catalog)
```

The signature fields describe a constrained token shape:

| Field | Meaning |
| --- | --- |
| `signature_id` | Stable lowercase identity used for catalog validation |
| `provider`, `secret_type` | Safe category metadata returned with findings |
| `prefixes` | One to sixteen literal token prefixes |
| `suffix_chars` | Exact printable-ASCII alphabet accepted after a prefix |
| `min_suffix_chars`, `max_suffix_chars` | Inclusive suffix-length bounds; prefer a finite maximum when the format defines one |
| `suffix_ending` | Optional required suffix tail within the permitted alphabet |
| `boundary_chars` | Token characters that prevent matching inside a larger identifier; must include all prefix and suffix characters |
| `source` | Non-secret provenance reference used to justify the format |
| `status` | `ACTIVE` or `LEGACY` lifecycle metadata |
| `severity`, `action` | Recommended handling before policy overrides |

Use the narrowest documented alphabet and length range. Broad alphabets or
unbounded lengths increase false-positive risk. Prefixes are literal and cannot
contain regex syntax; signature and catalog constructors reject invalid,
duplicate, oversized, or conflicting definitions.

The scanner never downloads or reads catalogs. The host application constructs
and pins the catalog before scanning, making updates testable and rollbackable.

The facade construction above adds the application catalog to the built-ins.
The extension's `catalog_id` and `version` identify the final effective
built-ins-plus-application catalog.

The resulting catalog is copied to each worker during startup and worker
recycling; it is not persisted or changed per request. Exact or nested built-in
prefix overlaps are rejected instead of weakening built-in coverage.
An advanced deployment that deliberately wants no built-ins must say so:

```python
firewall = Firewall(replacement_secret_catalog=complete_catalog)
```

The extension and replacement options are mutually exclusive. The earlier
ambiguous `secret_catalog=` facade keyword is intentionally unsupported before
the first release so an extension cannot silently disable built-in detection.

Clients can inspect a stable, immutable summary before startup:

```python
capabilities = firewall.capabilities()
print(capabilities.rule_count)
print(capabilities.secret_catalog.signature_count)
print(capabilities.secret_catalog.providers)
```

The summary includes rule IDs, purposes, scopes, policy identity, catalog
identity, counts, and provider names. It deliberately excludes literal secret
prefixes, source references, suffix alphabets, and matching internals. Treat
even this summary as operational metadata: a web service should expose only an
explicitly approved subset through an authenticated administrative endpoint.
Catalog creation is trusted startup configuration, not a per-request API.

## Runtime catalog updates

Services that need zero-downtime catalog changes should keep one
`FirewallManager` and route scans through it:

```python
from llm_ffw import FirewallManager

manager = FirewallManager()
manager.start()

# This is the complete desired application-extension snapshot, not a delta.
manager.reload(additional_secret_catalog=updated_additional_catalog)

safe_prompt = manager.sanitize_input(prompt)
safe_output = manager.sanitize_output(model_output)
```

Managers also provide `sanitize_input_result()` and
`sanitize_output_result()`. They return the same disclosure-safe
`SanitizationResult` as the direct facade while holding one immutable
generation lease for the complete request. The asynchronous manager exposes
matching awaitable result methods.

Asyncio services use the matching manager contract:

```python
from llm_ffw import AsyncFirewallManager

async def update_catalog(prompt: str) -> str:
    async with AsyncFirewallManager() as manager:
        capabilities = await manager.reload(
            additional_secret_catalog=updated_additional_catalog,
        )
        return await manager.sanitize_input(prompt)
```

`reload()`, `reload_builtin_catalog()`, `restart()`, and `close()` complete their
underlying lifecycle transition before propagating task cancellation, so a
caller never has to guess which generation became active.

Reload starts and verifies a new worker generation while the current generation
continues serving. It then atomically directs new requests to the new generation,
waits for requests already using the old generation, and closes the old workers.
If candidate construction or startup fails, the old generation remains active.
`reload_builtin_catalog()` removes application additions through the same safe
generation transition.

`reload()` returns the new immutable capabilities snapshot. On failure it raises
`FirewallReloadError`, whose `activated` flag distinguishes a rejected candidate
from a new generation that became active but encountered an old-generation
cleanup failure. Its bounded `cause_type` is safe for operational metrics; do
not treat a reload failure as permission to bypass inspection.

Every update must provide a newly versioned full snapshot containing all desired
application signatures, including previously configured ones. The manager does
not apply incremental patches. During a reload, both worker generations briefly
coexist, so deployments must reserve process and memory headroom. Reload is a
trusted administrative operation and must never be exposed directly to ordinary
request or tenant data.

## Development and validation

Python 3.14.7 or a newer 3.14 patch is required. This workspace is validated
with Python 3.14.7 using a local `.venv`:

```console
py -3.14 -m venv .venv
.venv\Scripts\python -m pip install ruff==0.16.3 mypy==2.3.0
.venv\Scripts\python -m ruff check llm_ffw tests benchmarks tools typing_tests
.venv\Scripts\python -m mypy
.venv\Scripts\python -m unittest discover -s tests -v
.venv\Scripts\python benchmarks/bench_scan.py --size 1000000 --rounds 5
.venv\Scripts\python benchmarks/generate_synthetic_dataset.py --size 8000000
.venv\Scripts\python benchmarks/bench_concurrent_scan.py --size 8000000 --workers 4 --requests 8
.venv\Scripts\python benchmarks/bench_policy.py --size 8000000 --rounds 3
.venv\Scripts\python benchmarks/bench_soak.py --size 8000000 --workers 4 --concurrency 8 --requests 32 --max-tasks-per-child 4
.venv\Scripts\python benchmarks/bench_async_facade.py --size 8000000 --workers 4 --concurrency 8 --requests 16 --max-tasks-per-child 4
.venv\Scripts\python benchmarks/bench_memory.py --size 8000000
.venv\Scripts\python benchmarks/bench_manager_reload.py --size 8000000 --workers 2 --concurrency 4 --reloads 4 --min-requests 16 --max-tasks-per-child 8
.venv\Scripts\python benchmarks/bench_mac_addresses.py --size 8000000 --rounds 3 --workers 2 --concurrency 4 --process-requests 8
.venv\Scripts\python benchmarks/bench_ibans.py --size 8000000 --rounds 3 --workers 2 --concurrency 4 --process-requests 8
.venv\Scripts\python benchmarks/bench_authorization_headers.py --size 8000000 --rounds 3 --workers 2 --concurrency 4 --process-requests 8
.venv\Scripts\python benchmarks/bench_connection_strings.py --size 8000000 --rounds 3 --workers 2 --concurrency 4 --process-requests 8
.venv\Scripts\python benchmarks/bench_credential_assignments.py --size 8000000 --rounds 3 --workers 2 --concurrency 4 --process-requests 8
.venv\Scripts\python benchmarks/bench_phone_numbers.py --size 8000000 --rounds 3 --workers 2 --concurrency 4 --process-requests 8
.venv\Scripts\python benchmarks/bench_repetition.py --size 8000000 --rounds 3 --workers 2 --concurrency 4 --process-requests 8
.venv\Scripts\python benchmarks/bench_bidi_controls.py --size 8000000 --rounds 3 --workers 2 --concurrency 4 --process-requests 8
.venv\Scripts\python benchmarks/bench_external_resources.py --size 8000000 --rounds 3 --workers 2 --concurrency 4 --process-requests 8
.venv\Scripts\python benchmarks/bench_tool_calls.py
.venv\Scripts\python benchmarks/bench_tool_results.py
.venv\Scripts\python tools/pii_accuracy_gate.py
.venv\Scripts\python benchmarks/generate_pii_accuracy_dataset.py
.venv\Scripts\python benchmarks/generate_all_rules_dataset.py --size 8000000
.venv\Scripts\python benchmarks/bench_all_rules.py --sizes 8192,131072,1000000,8000000 --workers 1,2,4 --catalog-patterns 1,100,1000
.venv\Scripts\python benchmarks/bench_all_rules.py --sizes 8000000 --profiles clean-input,clean-output-json --workers 4 --rule-sets default,all --rounds 3 --requests-per-worker 8 --concurrency-multiplier 2 --catalog-patterns 1 --max-tasks-per-child 1000 --timeout 240 --json-output benchmark.json
```

Mypy runs in strict mode over the library and typed public-API examples. CI
also checks the examples against the built wheel so the PEP 561 contract is
validated from a consumer installation, not only from the source tree.

The deterministic generator makes one match per catalog prefix plus near-miss
cases without LLM, network, provider, or random calls. Its manifest contains
expected spans and a digest, not corpus values. Benchmarks report only duration,
throughput, and finding counts; they never print scanned content. A release is
not approved until the exact candidate commit passes both Windows and Linux CI.

The PII accuracy gate deterministically evaluates 697 generated and curated
email-address, IP-address, MAC-address, IBAN, and phone-number scenarios. It requires exact
rule ownership, character spans, redaction output, precision, and recall, with
per-category confusion counts. Values use reserved example domains and
documentation or special-purpose IP ranges, locally administered synthetic
MAC values, and checksum-valid synthetic IBAN values for every registered
country length, plus conservative E.164-style synthetic phone values;
corpus creation makes no LLM or network calls. The
optional expanded JSONL corpus is written under the ignored
`benchmarks/generated/` directory, while the compact seed, group counts, and
expected digest remain version controlled.

The all-rules harness enables all 20 text rules in every worker and exercises
clean input, multilingual code/log-like input, valid JSON output, invalid JSON
output, sparse positives for every rule, dense bounded matches, and adversarial
near-misses. It verifies exact rule IDs, spans, and
actions before recording measurements. Its deterministic generator also
provides valid and invalid provider-neutral tool-call and tool-result fixtures.
Generated corpora remain under ignored `benchmarks/generated/`; manifests
contain only hashes, sizes, scopes, and expected metadata, never matched values.

Each benchmark result is one JSON object containing requests/second, aggregate
MiB/second, p50/p95/p99 end-to-end latency, p50 service time, p95 caller-queue
wait, cold-start and warm-up time, whole-process-tree peak RSS, process count,
and completion/rejection/timeout/failure counters. Use `--json-output` for a
machine-readable local report. `--catalog-patterns` measures literal-catalog
scaling separately from rule-count scaling. Large matrices are intentionally
local release evidence rather than a fixed CI threshold because shared CI
runner performance is not stable enough for absolute throughput gates.

## Production process concurrency

`ProcessScannerPool` is the supported multi-core execution boundary. It validates
worker execution before accepting traffic, uses a bounded in-flight queue,
recycles workers, returns only safe `Finding` objects, detects broken workers,
and shuts down deterministically.

```python
from llm_ffw import ProcessScannerPool, ProcessScannerPoolConfig, ScanScope

pool = ProcessScannerPool(
    pool_config=ProcessScannerPoolConfig(
        max_workers=4,
        max_in_flight=8,
        max_tasks_per_child=1_000,
    )
)
pool.start()  # Application startup/readiness hook.
try:
    findings = pool.scan(text, scope=ScanScope.INPUT, timeout=5)
finally:
    pool.shutdown(cancel_pending=True)  # Application shutdown hook.
```

For a bounded service termination window, begin with `shutdown()` early enough
to let active scans finish. Call `terminate()` at the grace deadline and reserve
`kill()` for the final hard-stop deadline.

Advanced integrations using the pool directly should call `pool.process(...)`
rather than `pool.scan(...)` to apply the configured policy. The balanced
default redacts secret findings; `STRICT_POLICY` blocks secret-bearing input
requests and `AUDIT_POLICY` reports without changing text. Blocking rejects one
request and does not stop workers.

Create one long-lived pool or manager per service instance, not one per request.
Map `ProcessPoolSaturatedError` to overload handling and treat a broken pool as
unhealthy.

## License

LLM FFW is licensed under the
[Apache License 2.0](LICENSE), including its explicit contributor patent grant
and patent-litigation termination terms.
