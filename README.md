# LLM FFW

**LLM FFW** (LLM Fast Firewall) is a high-speed deterministic rule engine for
scanning inputs entering and outputs leaving an LLM runtime.

The default scanner ships a secure baseline: `SecretsRule`, input-only
`InvisibleCharactersRule`, input-only `UnicodeTagSmugglingRule`,
`PaymentCardRule`, `PrivateKeyRule`, and `JWTTokenRule`. It detects constrained
credential formats, armored private-key blocks, and structurally credible
compact JWTs; canonicalizes contextual U+200B token obfuscation and non-RGI
Unicode tag runs; and redacts Luhn-valid payment-card candidates. Findings
retain original-text spans and safe category metadata rather than matched
values.

## Measured performance

Release `0.2.0` was benchmarked on GitHub-hosted Ubuntu and Windows runners
with Python 3.14.7. The test payload contains 8,000,000 synthetic ASCII
characters (about 7.63 MiB), representative of a million-token-scale prompt.
This is a size comparison rather than an exact token count: tokenization varies
by model, tokenizer, language, and content.

| Scenario | Ubuntu | Windows |
| --- | ---: | ---: |
| Single policy scan, median | 609 ms / 12.53 MiB/s | 637 ms / 11.97 MiB/s |
| Concurrent soak, 4 workers and 8 callers | 3.33 requests/s | 3.19 requests/s |
| Concurrent aggregate throughput | 25.41 MiB/s | 24.37 MiB/s |
| Separate single-process memory benchmark, peak RSS | 47.22 MiB | 48.77 MiB |

The concurrent soak processed 32 complete payloads, validated every result,
and recycled each worker after four tasks. These are reproducible CI
measurements, not universal latency guarantees; performance varies with input,
enabled rules, policy, CPU, and concurrency. See the
[exact release-gate run](https://github.com/wyezee/llm-ffw/actions/runs/31952014903)
and the commands under [Development and validation](#development-and-validation).

## Installation

LLM FFW requires Python 3.14.7 or a newer Python 3.14 patch release. It has no
runtime dependencies outside the Python standard library.

```console
python -m pip install llm-ffw
```

Pin the version in production dependency files. To use the complete synchronous
and asynchronous API documented here, install `llm-ffw==0.3.0`. The performance
table above remains explicitly attributed to release `0.2.0`.

## Usage

Choose the highest-level API that fits the integration:

| API | Use it for |
| --- | --- |
| `LLMFirewall` | Recommended production input/output sanitization and lifecycle |
| `AsyncLLMFirewall` | The same production contract for asyncio applications |
| `LLMFirewallManager` | The same facade with zero-downtime secret-catalog reloads |
| `AsyncLLMFirewallManager` | Asyncio sanitization plus asynchronous catalog lifecycle |
| `FirewallStream` | Chunked input with explicit incremental or buffered enforcement |
| `Firewall` | Same-process scanning plus policy application |
| `Scanner` | Same-process detection when the host applies findings itself |
| `ProcessScannerPool` | Advanced process orchestration and explicit overload control |

Production integrations should use `LLMFirewall`. Its balanced default redacts
detected secrets in both directions while preserving flow:

```python
from llm_ffw import LLMFirewall

def main() -> None:
    with LLMFirewall() as firewall:
        safe_prompt = firewall.sanitize_input(prompt)
        model_output = call_model(safe_prompt)
        safe_output = firewall.sanitize_output(model_output)

if __name__ == "__main__":
    main()
```

Create one facade during application startup and reuse it for every request.
Call `start()` and `close()` from a long-lived application's lifecycle hooks;
the context-manager form is convenient for scripts and batch jobs. Standalone
programs must protect their entry point with `if __name__ == "__main__":`
because the facade uses worker processes.

### Unified streaming

`FirewallStream` accepts chunked text without changing the meaning of the
configured scanner or policy. The default `AUTO` mode emits incrementally only
when every active rule and effective action can safely do so; otherwise it
buffers the request and applies the normal firewall at `finish()`:

```python
from llm_ffw import Firewall

firewall = Firewall()
stream = firewall.stream()
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
from llm_ffw import Firewall, Scanner, StreamMode
from llm_ffw.rules import SecretsRule

firewall = Firewall(scanner=Scanner(rules=(SecretsRule(),)))
stream = firewall.stream(mode=StreamMode.INCREMENTAL)
```

The current release has a fused incremental implementation for `SecretsRule`.
Other active rules are reported as `StreamingSupport.END_OF_STREAM` and cause
`AUTO` to buffer or `INCREMENTAL` to reject. This is a capability boundary, not
a security downgrade; more rules can gain incremental implementations behind
the same API without changing client integration. Inspect `execution_mode` and
`rule_capabilities` before accepting traffic when deployment behavior depends
on early emission. `StreamMode.BUFFERED` can be selected to require full batch
semantics explicitly.

Incremental secret execution requires an effective `REDACT` action because
previously emitted text cannot be recalled. Candidate shapes that would need
attacker-sized retention also fall back to buffered execution in `AUTO` mode.
Findings retain spans into the original concatenated text and disclosure-safe
metadata. Each stream belongs to one request and must not be shared between
concurrent callers.

### Async usage

Asyncio applications should use `AsyncLLMFirewall` directly instead of wrapping
the synchronous facade with `asyncio.to_thread()`:

```python
from llm_ffw import AsyncLLMFirewall

async def handle_request(firewall: AsyncLLMFirewall, prompt: str) -> str:
    safe_prompt = await firewall.sanitize_input(prompt)
    model_output = await call_model_async(safe_prompt)
    return await firewall.sanitize_output(
        model_output,
        prompt_context=safe_prompt,
    )

async def main(prompt: str) -> None:
    async with AsyncLLMFirewall() as firewall:
        response = await handle_request(firewall, prompt)
```

In a service, create and start one async facade during application startup,
reuse it for requests, and await `close()` during shutdown. It supports async
`start()`, `close()`, `terminate()`, `kill()`, input/output sanitization, and
structured-result methods. `capabilities()` and `state` remain synchronous
because they return in-memory metadata without blocking.

The async facade uses the same process scanner, policies, configuration,
timeouts, and exceptions as `LLMFirewall`. Its private request executor and
async admission gate are both bounded by `ProcessScannerPoolConfig`; it never
blocks the event loop while waiting for CPU workers. One instance belongs to
one event loop. Canceling an await does not abandon its running scan: the scan
finishes under the configured request timeout and retains its capacity slot
until completion, preventing cancellation-driven queue growth.

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

`Firewall`, `ProcessScannerPool`, and `Scanner` remain lower-level APIs for
custom policy results, process orchestration, and detection-only evaluation.

```python
from llm_ffw import ScanScope, Scanner

scanner = Scanner()
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
context are each bounded by `ScannerConfig.max_input_chars`.

Do not log `text` or slice a finding's span for diagnostics. Findings contain a
category-only `redacted_preview` suitable for reporting.

The default `ScannerConfig.max_input_chars` is 8,000,000 characters, providing
headroom for a typical one-million-token text context. Token-to-character ratios
vary by model, language, and content; callers should still set an explicit limit
appropriate to their deployment and memory budget.

## Facade configuration

`LLMFirewall` and `AsyncLLMFirewall` accept the same immutable startup
configuration. Create and validate one facade, then reuse it rather than
rebuilding it per request.

| Constructor parameter | Purpose |
| --- | --- |
| `scanner_config` | Input limit, redaction marker, and default-rule enable flags |
| `pool_config` | Worker count, bounded in-flight capacity, recycling, and admission timeout |
| `additional_secret_catalog` | Add organization signatures while retaining all built-ins |
| `replacement_secret_catalog` | Deliberately replace the complete built-in secret catalog |
| `banned_substring_catalog` | Enable a deployment-owned immutable literal catalog |
| `json_output_config` | Enable bounded output-only JSON validation |
| `unsafe_url_config` | Enable bounded input/output URL inspection |
| `payment_card_config` | Customize enabled payment-card limits and scopes |
| `private_key_config` | Customize enabled private-key limits and scopes |
| `jwt_token_config` | Customize enabled JWT limits and scopes |
| `policy` | Select balanced, strict, audit, or a versioned custom policy |
| `request_timeout_seconds` | Per-request facade deadline; defaults to 5 seconds |

The two secret-catalog parameters are mutually exclusive. Passing `None` for
the opt-in banned-substring, JSON, and unsafe-URL configurations leaves those
rules disabled. Payment-card, private-key, JWT, invisible-character, and Unicode
tag rules are enabled by `ScannerConfig` defaults; their dedicated config
objects customize bounds and scopes rather than enabling them.

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
`LLMFirewall(policy=STRICT_POLICY)`. Use a custom policy only when a deployment
needs an explicit rule-and-scope exception:

```python
from llm_ffw import (
    Action,
    FirewallPolicy,
    LLMFirewall,
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
firewall = LLMFirewall(
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
| `unicode.invisible_characters` | Enabled | Input | Remove; block bounded overflow | `ScannerConfig` |
| `unicode.tag_smuggling` | Enabled | Input | Remove; block bounded overflow | `ScannerConfig` |
| `pii.payment_card` | Enabled | Input/output | Redact | `PaymentCardConfig` |
| `secrets.private_key` | Enabled | Input/output | Redact complete blocks; block unsafe malformed cases | `PrivateKeyConfig` |
| `secrets.jwt_token` | Enabled | Input/output | Redact | `JWTTokenConfig` |
| `content.banned_substrings` | Opt-in | Catalog-defined | Pattern action; redact by default | `BannedSubstringCatalog` |
| `output.json.validity` | Opt-in | Output | Block | `JSONOutputConfig` |
| `url.unsafe` | Opt-in | Input/output by default | Redact | `UnsafeURLConfig` |

### Default invisible-character canonicalization

`InvisibleCharactersRule` removes a U+200B zero-width-space
run only when it is embedded between ASCII token characters, then rescans the
cleaned input through every enabled rule. Clean ASCII requests retain a single
scan. The rule is input-only and enabled by default. Applications can opt out:

```python
from llm_ffw import LLMFirewall, ScannerConfig

firewall = LLMFirewall(
    scanner_config=ScannerConfig(enable_invisible_characters=False),
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
`ScannerConfig(enable_unicode_tag_smuggling=False)`. More than 64 relevant runs
fails closed.

### Deployment-defined banned substrings

An optional immutable `BannedSubstringCatalog` provides constrained substring
or ASCII-word matching for input and output. It defaults to redaction and never
accepts caller regex.

```python
from llm_ffw import (
    Action,
    BannedSubstring,
    BannedSubstringCatalog,
    LLMFirewall,
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
firewall = LLMFirewall(banned_substring_catalog=content_catalog)
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
from llm_ffw import JSONOutputConfig, LLMFirewall

firewall = LLMFirewall(json_output_config=JSONOutputConfig())
```

Malformed syntax, duplicate keys, non-standard non-finite constants, and
configured resource-limit violations block by default. The rule does not
extract JSON from Markdown or repair malformed output.

### Opt-in unsafe URL inspection

Applications that pass model-produced URLs to users or downstream tools can
enable bounded structural URL inspection:

```python
from llm_ffw import LLMFirewall, UnsafeURLConfig

firewall = LLMFirewall(unsafe_url_config=UnsafeURLConfig())
```

`UnsafeURLRule` redacts dangerous schemes, embedded URL user-info, local or
non-public IP targets, exact documented cloud metadata hostnames, and ambiguous
authorities under balanced policy. It checks input and output by default;
deployments can restrict its `scopes`. It performs no DNS, HTTP, reputation,
model, or other network call.

### Default payment-card inspection

Bounded Luhn-based payment-card inspection is enabled in both directions by
default. Applications can customize its limits and scopes:

```python
from llm_ffw import LLMFirewall, PaymentCardConfig

firewall = LLMFirewall(payment_card_config=PaymentCardConfig())
```

`PaymentCardRule` redacts structurally plausible 13–19 digit ASCII candidates
under balanced policy. Luhn is a checksum, not proof that a card exists or is
active. Applications that intentionally pass checksum-valid identifiers or test
cards can opt out with `ScannerConfig(enable_payment_cards=False)`.

### Supported secret signatures

Armored private-key inspection is independently enabled by default for input
and output. Balanced policy redacts complete blocks and safely contains
malformed or oversized blocks. Applications can customize bounded limits with
`PrivateKeyConfig` or explicitly opt out with
`ScannerConfig(enable_private_keys=False)`.

Compact JWT inspection is also enabled by default. It validates canonical
Base64URL, unique-member JSON header/payload objects, algorithm/signature
consistency, and JWT-specific type or registered-claim evidence before
redaction. It does not verify signatures or trust claims. Applications can
customize bounded limits with `JWTTokenConfig` or opt out with
`ScannerConfig(enable_jwt_tokens=False)`.

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

from llm_ffw import LLMFirewall, SecretCatalog, SecretSignature

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
firewall = LLMFirewall(additional_secret_catalog=additional_catalog)
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
firewall = LLMFirewall(replacement_secret_catalog=complete_catalog)
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
`LLMFirewallManager` and route scans through it:

```python
from llm_ffw import LLMFirewallManager

manager = LLMFirewallManager()
manager.start()

# This is the complete desired application-extension snapshot, not a delta.
manager.reload(additional_secret_catalog=updated_additional_catalog)

safe_prompt = manager.sanitize_input(prompt)
safe_output = manager.sanitize_output(model_output)
```

Asyncio services use the matching manager contract:

```python
from llm_ffw import AsyncLLMFirewallManager

async def update_catalog(prompt: str) -> str:
    async with AsyncLLMFirewallManager() as manager:
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
.venv\Scripts\python -m unittest discover -s tests -v
.venv\Scripts\python benchmarks/bench_scan.py --size 1000000 --rounds 5
.venv\Scripts\python benchmarks/generate_synthetic_dataset.py --size 8000000
.venv\Scripts\python benchmarks/bench_concurrent_scan.py --size 8000000 --workers 4 --requests 8
.venv\Scripts\python benchmarks/bench_policy.py --size 8000000 --rounds 3
.venv\Scripts\python benchmarks/bench_soak.py --size 8000000 --workers 4 --concurrency 8 --requests 32 --max-tasks-per-child 4
.venv\Scripts\python benchmarks/bench_async_facade.py --size 8000000 --workers 4 --concurrency 8 --requests 16 --max-tasks-per-child 4
.venv\Scripts\python benchmarks/bench_memory.py --size 8000000
.venv\Scripts\python benchmarks/bench_manager_reload.py --size 8000000 --workers 2 --concurrency 4 --reloads 4 --min-requests 16 --max-tasks-per-child 8
```

The deterministic generator makes one match per catalog prefix plus near-miss
cases without LLM, network, provider, or random calls. Its manifest contains
expected spans and a digest, not corpus values. Benchmarks report only duration,
throughput, and finding counts; they never print scanned content. A release is
not approved until the exact candidate commit passes both Windows and Linux CI.

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
