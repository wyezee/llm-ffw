# LLM FFW

**LLM FFW** (LLM Fast Firewall) is a high-speed deterministic rule engine for
scanning inputs entering and outputs leaving an LLM runtime. Its runtime uses
only the Python standard library: no model judge, network calls, probabilistic
classification, or third-party packages.

The default scanner ships a secure baseline: `SecretsRule`, input-only
`InvisibleCharactersRule`, input-only `UnicodeTagSmugglingRule`,
`PaymentCardRule`, `PrivateKeyRule`, and `JWTTokenRule`. It detects constrained
credential formats, armored private-key blocks, and structurally credible
compact JWTs; canonicalizes contextual U+200B token obfuscation and non-RGI
Unicode tag runs; and redacts Luhn-valid payment-card candidates. Findings
retain original-text spans and safe category metadata rather than matched
values.

## Usage

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

## Deployment-defined banned substrings

An optional immutable `BannedSubstringCatalog` provides constrained substring
or ASCII-word matching for input and output. It defaults to redaction and never
accepts caller regex.

## Opt-in JSON output validation

Applications that require a complete JSON response can enable the bounded,
output-only `JSONOutputRule`:

```python
from llm_ffw import JSONOutputConfig, LLMFirewall

firewall = LLMFirewall(json_output_config=JSONOutputConfig())
```

Malformed syntax, duplicate keys, non-standard non-finite constants, and
configured resource-limit violations block by default. The rule does not
extract JSON from Markdown or repair malformed output.

## Opt-in unsafe URL inspection

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

## Default payment-card inspection

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

## Supported secret signatures

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

Reload starts and verifies a new worker generation while the current generation
continues serving. It then atomically directs new requests to the new generation,
waits for requests already using the old generation, and closes the old workers.
If candidate construction or startup fails, the old generation remains active.
`reload_builtin_catalog()` removes application additions through the same safe
generation transition.

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
