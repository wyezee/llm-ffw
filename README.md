# LLM FFW

**LLM FFW** (LLM Fast Firewall) is a high-speed deterministic rule engine for
scanning inputs entering and outputs leaving an LLM runtime. Its runtime uses
only the Python standard library: no model judge, network calls, probabilistic
classification, or third-party packages.

Milestone 1 intentionally ships one rule. `SecretsRule` detects a narrow set of
credentials in text with well-known prefixes and returns original-text spans
plus safe redaction metadata. Future milestones may add structured and other
payload types without changing the deterministic rule contract.

## Usage

```python
from llm_ffw import Scanner

scanner = Scanner()
text = get_llm_input()  # Your application supplies the text.

findings = scanner.scan(text)
for finding in findings:
    print(finding.rule_id, finding.severity.value, finding.span)

safe_text = scanner.redact(text, findings)
```

Do not log `text` or slice a finding's span for diagnostics. Findings contain a
category-only `redacted_preview` suitable for reporting.

## Supported secret signatures

- OpenAI-style keys beginning with `sk-`, including `proj-` and `svcacct-`
  variants
- GitHub tokens with documented `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_`
  prefixes
- AWS access-key IDs beginning with `AKIA` or `ASIA`

The rule does not attempt generic password or entropy detection. See
[`docs/rule-contract.md`](docs/rule-contract.md) for the exact contract and
limitations.

## Development and validation

Python 3.11 or newer is required.

```console
python -m unittest discover -s tests -v
python benchmarks/bench_scan.py --size 1000000 --rounds 5
```

The benchmark reports only duration, throughput, and finding count; it never
prints scanned content. Design decisions are documented in
[`docs/design.md`](docs/design.md).
