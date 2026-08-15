# Changelog

All notable changes are recorded here before a tagged release.

## Unreleased

### Added

- Opt-in `InvisibleCharactersRule` with contextual U+200B removal, bounded
  findings, compact original-span mapping, and one remove-then-rescan pass.
- Explicit `REMOVE` policy action and focused clean/dirty/process performance
  benchmark with Windows/Linux release tripwires.
- Built-in policy profiles `1.1.0` with balanced remove, strict block, and
  audit review handling for the opt-in rule.

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
