# Changelog

All notable changes are recorded here before a tagged release.

## Unreleased

## 0.12.0 - 2026-08-19

- Detect lowercase and mixed-case IBAN representations without changing their
  original redaction spans.
- Recognize indented Authorization headers and redact malformed,
  non-placeholder Basic and Bearer credentials instead of failing open.
- Correct ASCII email boundaries, leading-period handling, email candidate
  accounting, and explicit `MAC:` label detection.
- Make excessive-line repetition detection consistent for every supported
  Unicode line separator, including its bounded streaming fallback.
- Reject zero request deadlines and unbounded admission waits, and raise the
  default process-facade request deadline from 5 to 30 seconds.
- Guarantee async worker cleanup across cancellation, cleanup failures, and
  shutdown calls made from a different event loop.
- Accelerate IPv6 candidate discovery with a fixed linear prefilter and emit a
  fail-closed finding for token runs beyond the 45-character parser bound.
- Require every object in the supported tool-call schema subset to declare an
  explicit boolean `additionalProperties` policy.
- Inspect tool-call arguments as outbound text and tool-result content as
  inbound text with the deterministic scanner baseline, blocking on findings.
- Enforce configured tool-call, per-result, and aggregate result-batch budgets
  while copying untrusted structured values into immutable trees.

## 0.11.1 - 2026-08-19

### Changed

- Skip impossible IPv6 candidate traversal when text contains fewer than two
  colons, and accelerate common token classification in `RepetitionRule`
  without changing findings or configured limits.

## 0.11.0 - 2026-08-19

### Added

- Added an explicitly packaged PEP 561 `py.typed` marker plus installed-wheel
  checks for canonical public API annotations.
- Added strict mypy checks for all runtime modules and typed synchronous,
  asynchronous, streaming, configuration, and structured-tool consumer
  examples, including verification against the installed wheel.
- Added a pinned Ruff correctness gate, GitHub CodeQL scanning for Python and
  Actions workflows, and weekly Dependabot maintenance for pinned Actions.

### Changed

- Made internal configuration forwarding, heterogeneous rule collections,
  immutable JSON validation, async future tracking, and streaming invariants
  statically precise without adding runtime dependencies.

### Documentation

- Added copy-paste recipes to the README and a tested `EXAMPLES.md` guide for
  the production facades, presets, lower-level rule APIs, streaming, catalog
  reloads, and direct process-pool orchestration.

## 0.10.0 - 2026-08-18

### Changed

- Upgraded artifact upload and download actions to their SHA-pinned,
  Node 24-compatible v7 releases for future workflows.
- Added a top-level rule matrix documenting activation, default scope,
  balanced-policy handling, and supported policy choices.
- Made `Firewall`, `AsyncFirewall`, `FirewallManager`, and
  `AsyncFirewallManager` the canonical production facades; renamed the
  detection-only engine to `RuleScanner` and the in-process scan-and-policy
  class to `RuleEngine`.
- **Breaking:** package-root `Firewall` now identifies the production facade.
  Code using the former low-level `Firewall(scanner=..., policy=...)` must use
  `RuleEngine(scanner=..., policy=...)`.

### Deprecated

- `LLMFirewall`, `AsyncLLMFirewall`, `LLMFirewallManager`,
  `AsyncLLMFirewallManager`, `Scanner`, and `ScannerConfig` remain compatibility
  aliases for their canonical replacements during the pre-1.0 migration
  window.

## 0.9.0 - 2026-08-18

### Added

- Immutable `FirewallConfig` presets shared by synchronous, asynchronous, and
  hot-reload facades, plus structured sanitization-result parity for both
  manager APIs.
- Repeated default-versus-all-rules publication benchmarking with pooled
  latency percentiles, safe environment provenance, and an on-demand Windows
  and Ubuntu evidence workflow.
- Deterministic all-rules benchmark corpora and a production-concurrency
  harness covering all 15 text rules plus structured tool fixtures, exact
  expectation checks, latency percentiles, queue/service timing, process-tree
  memory, lifecycle timing, saturation counters, and catalog-size scaling.

### Changed

- Refreshed the SHA-pinned artifact transfer actions used by Trusted
  Publishing to their v5 releases.

## 0.8.0 - 2026-08-18

### Added

- Opt-in `RepetitionRule` for conservative exact non-whitespace character,
  token, and non-empty line runs, with immutable thresholds, review-first
  findings, bounded-memory fallbacks, facade/capability integration, and an
  8 MB concurrent performance envelope.
- Opt-in `AuthorizationHeaderRule` for exact line-oriented HTTP Basic and
  Bearer credentials, with bounded parsing, credential-only redaction,
  disclosure-safe findings, facade/policy/capability integration, and an 8 MB
  performance envelope.

## 0.7.0 - 2026-08-17

### Added

- Provider-neutral `ToolCallRule` with immutable typed calls, declared-tool
  allowlisting, a deliberately bounded JSON-Schema subset, disclosure-safe
  fail-closed findings, and configurable depth, node, string, object, and
  array limits.
- Provider-neutral `ToolResultRule` with immutable typed result batches,
  call-ID linkage and uniqueness checks, exact tool-name consistency, bounded
  string or JSON object-block content, and disclosure-safe fail-closed
  findings.
- Opt-in `IBANRule` pinned to SWIFT IBAN Registry Release 102, with exact
  registered-country lengths, canonical electronic and print forms, streaming
  MOD-97 validation, bounded candidate handling, policy/capability integration,
  exhaustive registered-country tests, and an 8 MB performance envelope.

## 0.6.0 - 2026-08-17

### Fixed

- Keep the public runtime `llm_ffw.__version__` value synchronized with the
  installed distribution version and enforce that invariant in release smoke
  testing.

### Added

- Opt-in bounded `MACAddressRule` for canonical 48-bit colon- and
  hyphen-separated address privacy redaction, with input-only defaults,
  policy/capability integration, a deterministic 480-scenario PII accuracy
  corpus, and an 8 MB production performance envelope.

## 0.5.1 - 2026-08-17

### Added

- Deterministic 364-scenario PII accuracy and exact-redaction gate for the
  opt-in email-address and IP-address rules, combining generated coverage with
  curated syntax boundaries and realistic near misses, using only synthetic
  examples and no LLM or network calls.

### Fixed

- Detect canonical IPv4 and IPv6 addresses followed by a sentence period while
  continuing to reject dotted identifier suffixes.

## 0.5.0 - 2026-08-17

### Added

- Opt-in bounded `EmailAddressRule` for conservative ASCII mailbox privacy
  redaction, with input-only defaults, scope controls, safe metadata, policy
  integration, public capabilities, and an 8 MB production envelope.
- Opt-in bounded `IPAddressRule` for canonical IPv4 and IPv6 privacy
  redaction, with input-only defaults, family/scope controls, safe metadata,
  policy integration, public capabilities, and an 8 MB production envelope.

## 0.4.0 - 2026-08-16

### Added

- Unified incremental `FirewallStream` execution for `SecretsRule` and
  `PaymentCardRule`, with batch-equivalent findings, merged redaction,
  boundary-safe chunk handling, and bounded normal-path buffering.

## 0.3.0 - 2026-08-16

### Added

- `AsyncLLMFirewall` with async input/output sanitization, structured results,
  bounded admission, cancellation-safe capacity accounting, and managed
  process lifecycle without blocking the application event loop.
- `AsyncLLMFirewallManager` with asynchronous sanitization, catalog reload,
  built-in catalog refresh, restart, and generation shutdown.
- Cross-platform 8 MB async responsiveness and throughput release gate plus
  isolated-wheel export validation.

## 0.2.0 - 2026-08-16

### Changed

- Promote the fully validated `0.2.0rc3` code to the stable `0.2.0` release
  without runtime behavior changes.

## 0.2.0rc3 - 2026-08-16

### Changed

- Unsafe URL candidate discovery is linear for overlapping scheme markers, and
  secret findings now fail closed after a bounded 128 candidates.
- Custom secret signatures require suffix characters to be boundary characters,
  preventing deployment catalogs from introducing repeated suffix rescans.
- A request timeout quarantines and terminates its complete worker generation;
  `LLMFirewallManager.restart()` can replace broken generations with identical
  catalog configuration. High-level facades now require a finite timeout.

## 0.2.0rc2 - 2026-08-16

### Added

- `LLMFirewall.sanitize_input_result()` and `sanitize_output_result()` return
  forwardable sanitized text with disclosure-safe findings, effective policy
  metadata, and decisions while preserving fail-closed exceptions.

### Changed

- The primary multiprocessing quickstart now includes the required standalone
  entry-point guard.

## 0.2.0rc1 - 2026-08-16

### Added

- Default input-only `UnicodeTagSmugglingRule` with bounded removal and rescan,
  Unicode Emoji 17.0 RGI subdivision-flag preservation, disclosure-safe
  findings, independent opt-out, and 8 MB adversarial/process gates. Built-in
  policy profiles advance to `1.7.0`.

- Default bounded `JWTTokenRule` detection and redaction for compact JWTs with
  canonical Base64URL, unique-member JSON, algorithm, and JWT-type/registered-
  claim validation. Built-in policy profiles advance to `1.6.0`.

- Default bounded `PrivateKeyRule` detection and redaction for armored PEM,
  OpenSSH, and OpenPGP private-key blocks, including explicit opt-out,
  disclosure-safe capabilities, malformed-block containment, and performance
  coverage. Built-in policy profiles advance to `1.5.0`.

- Input/output `PaymentCardRule` with bounded ASCII candidate matching,
  Luhn validation, configurable scopes, safe full-span redaction, and no
  issuer, network, or model lookup.
- Built-in policy profiles `1.4.0` redact payment-card findings under balanced
  policy, block them under strict policy, and report them under audit policy.
- Cross-platform 8 MB payment-card clean, adversarial, redaction, memory, and
  concurrent process-pool release gates.

- Opt-in input/output `UnsafeURLRule` with configurable scopes and bounded
  structural parsing for dangerous schemes, embedded authority credentials,
  local targets, exact documented Google and Tencent cloud metadata hostnames,
  and ambiguous authorities; no DNS, HTTP, model, or reputation calls.
- Built-in policy profiles `1.3.0` redact unsafe URLs under balanced policy,
  block them under strict policy, and report them under audit policy.
- Cross-platform 8 MB unsafe-URL clean, adversarial, redaction, memory, and
  concurrent process-pool release gates.
- Opt-in `JSONOutputRule` for strict complete-document validation with bounded
  depth and structure, safe failure metadata, process propagation, and
  conditional post-policy validation after transformations.
- Built-in policy profiles `1.2.0` block invalid expected JSON by default and
  report it under audit policy.

- Optional `BannedSubstringsRule` with versioned caller-owned literal catalogs,
  prefix-factored matching, bounded findings, process propagation, and safe
  capability summaries.

- `InvisibleCharactersRule` with contextual U+200B removal, bounded
  findings, compact original-span mapping, and one remove-then-rescan pass.
- Explicit `REMOVE` policy action and focused clean/dirty/process performance
  benchmark with Windows/Linux release tripwires.
- Built-in policy profiles `1.1.0` with balanced remove, strict block, and
  audit review handling for the rule.

### Changed

- Shared Unicode canonicalization now builds replacement text and original-span
  mappings lazily, preserving the clean-input fast path while keeping bounded
  remove-and-rescan behavior.

### Fixed

- Linux manager-reload memory sampling now tolerates worker processes exiting
  between procfs enumeration and inspection.

## 0.1.0 - 2026-08-15

### Added

- High-level `LLMFirewall` facade with simple input/output sanitization, managed
  process lifecycle, and safe block/unavailable exceptions.
- Immutable facade capability summaries and deployment-pinned custom secret
  catalogs propagated through worker startup and recycling.
- Safe-by-default built-in catalog extension and an explicitly named complete
  replacement path; ambiguous facade replacement is not supported.
- `LLMFirewallManager` for readiness-gated, atomic runtime catalog generations
  with old-request draining and safe reload failure metadata.
- Apache License 2.0 package and distribution metadata.
- Deterministic `SecretsRule` with catalog `3.0.0`: 28 signatures, 47
  prefixes, and 13 providers.
- Input/output scan scopes and shared inspection planning.
- Balanced, strict, and audit policy profiles with one-pass redaction.
- Bounded process concurrency with readiness, overload, recycling, graceful
  shutdown, forced termination, and broken-worker detection.
- Deterministic 8 MB synthetic data, concurrency, policy, soak/recycling, and
  peak-memory benchmarks.
- Concurrent 8 MB atomic-reload release gate covering request accounting,
  generation isolation, rollback, peak process-tree memory, leaks, and shutdown.
- Isolated wheel-install smoke testing and Windows/Linux CI definitions.

### Changed

- The secure default baseline now enables `SecretsRule`, input-only
  `InvisibleCharactersRule`, and `PaymentCardRule`; explicit scanner flags can
  disable either non-secret rule.
- The default input limit is 8,000,000 characters.
- Python 3.14.7 or newer is required.
- Balanced policy redacts secret findings in both directions by default.

### Security

- Findings and benchmark output contain category metadata, never matched
  secret text.
- Catalogs accept constrained literal signatures instead of arbitrary regular
  expressions or executable callbacks.
- Twilio API-key SIDs are excluded because they are identifiers rather than
  independently authenticating secrets.
