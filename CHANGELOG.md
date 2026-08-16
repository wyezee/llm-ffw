# Changelog

All notable changes are recorded here before a tagged release.

## Unreleased

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
