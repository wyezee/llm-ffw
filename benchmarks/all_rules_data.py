"""Deterministic synthetic corpora for every text and structured rule.

The values are intentionally nonfunctional and use reserved documentation
names and address ranges.  Corpus construction performs no network, model, or
random calls.
"""

from dataclasses import dataclass, field
import hashlib
import json

from llm_ffw import ScanScope, ToolCall, ToolDefinition, ToolResult, ToolResultBatch


BANNED_MARKER = "benchmark_forbidden_literal"
ALL_TEXT_RULE_IDS = frozenset(
    {
        "secrets.detected",
        "unicode.invisible_characters",
        "unicode.tag_smuggling",
        "pii.payment_card",
        "secrets.private_key",
        "secrets.jwt_token",
        "content.banned_substrings",
        "output.json.validity",
        "url.unsafe",
        "pii.ip_address",
        "pii.mac_address",
        "pii.iban",
        "secrets.authorization_header",
        "pii.email_address",
        "pii.phone_number",
        "text.excessive_repetition",
    }
)


@dataclass(frozen=True, slots=True)
class ExpectedFinding:
    """Expected rule ownership and original-text span."""

    rule_id: str
    start: int
    end: int
    action: str = "redact"


@dataclass(frozen=True, slots=True)
class TextScenario:
    """One exact-size text corpus with disclosure-safe expectations."""

    scenario_id: str
    profile: str
    scope: ScanScope
    text: str = field(repr=False)
    expected: tuple[ExpectedFinding, ...] = ()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class StructuredScenarios:
    """Valid and invalid provider-neutral tool payloads."""

    definition: ToolDefinition
    valid_call: ToolCall
    invalid_call: ToolCall
    valid_result: ToolResultBatch
    invalid_result: ToolResultBatch


def _pad(parts: list[str], size: int, *, unit: str) -> str:
    current = sum(map(len, parts))
    if current > size:
        raise ValueError(f"size {size} is too small; scenario needs {current} characters")
    label = unit.strip() or "safe"
    index = 0
    while current < size:
        line = f"{label} {index:08d}\n"
        fragment = line[: size - current]
        parts.append(fragment)
        current += len(fragment)
        index += 1
    text = "".join(parts)
    if len(text) != size:
        raise RuntimeError("all-rules corpus length invariant failed")
    return text


def _append(
    parts: list[str],
    expected: list[ExpectedFinding],
    rule_id: str,
    value: str,
    *,
    prefix: str = "",
    suffix: str = "\n",
    action: str = "redact",
) -> None:
    start = sum(map(len, parts)) + len(prefix)
    parts.extend((prefix, value, suffix))
    expected.append(ExpectedFinding(rule_id, start, start + len(value), action))


def _tagged(value: str) -> str:
    return "".join(chr(0xE0000 + ord(character)) for character in value)


def _positive_input(size: int) -> TextScenario:
    parts: list[str] = []
    expected: list[ExpectedFinding] = []
    _append(parts, expected, "secrets.detected", "sk-" + "A" * 20, prefix="token=")
    _append(
        parts,
        expected,
        "unicode.invisible_characters",
        "\u200b",
        prefix="hello",
        suffix="world\n",
        action="remove",
    )
    _append(
        parts,
        expected,
        "unicode.tag_smuggling",
        _tagged("hidden"),
        prefix="visible",
        action="remove",
    )
    _append(parts, expected, "pii.payment_card", "4242424242424242", prefix="card=")
    key = "-----BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUA==\n-----END PRIVATE KEY-----"
    _append(parts, expected, "secrets.private_key", key)
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJzeW50aGV0aWMtdXNlciJ9.c2lnbmF0dXJl"
    )
    _append(parts, expected, "secrets.jwt_token", jwt, prefix="jwt: ")
    _append(parts, expected, "content.banned_substrings", BANNED_MARKER)
    # The unsafe URL deliberately contains an IPv4 finding as well.
    url = "http://127.0.0.1/benchmark"
    url_start = sum(map(len, parts))
    parts.extend((url, "\n"))
    expected.extend(
        (
            ExpectedFinding("url.unsafe", url_start, url_start + len(url)),
            ExpectedFinding(
                "pii.ip_address",
                url_start + len("http://"),
                url_start + len("http://127.0.0.1"),
            ),
        )
    )
    _append(parts, expected, "pii.mac_address", "02:00:00:00:00:01", prefix="mac=")
    _append(parts, expected, "pii.iban", "GB29NWBK60161331926819", prefix="iban=")
    bearer = "synthetic_bearer_token_123456"
    _append(
        parts,
        expected,
        "secrets.authorization_header",
        bearer,
        prefix="Authorization: Bearer ",
    )
    _append(parts, expected, "pii.email_address", "benchmark.user@example.com", prefix="email=")
    _append(parts, expected, "pii.phone_number", "+999000000000001", prefix="phone=")
    repeated = "repeat " * 64
    _append(
        parts,
        expected,
        "text.excessive_repetition",
        repeated,
        prefix="sequence: ",
        action="review",
    )
    expected[-1] = ExpectedFinding(
        expected[-1].rule_id,
        expected[-1].start,
        expected[-1].end - 1,
        expected[-1].action,
    )
    return TextScenario(
        "sparse-input",
        "sparse",
        ScanScope.INPUT,
        _pad(parts, size, unit="safe benchmark prose line\n"),
        tuple(expected),
    )


def _near_miss_input(size: int) -> TextScenario:
    parts = [
        "sk-AAAAAAAAAAAAAAAAAAA\n",
        "Card 4242424242424241\n",
        "email user_at_example_dot_com\n",
        "phone +44 20 7946 0958\n",
        "IP 999.1.1.1\n",
        "MAC 00:11:22:33:44\n",
        "IBAN GB29NWBK60161331926818\n",
        "Authorization: Bearer <token>\n",
        "https://example.com/safe\n",
        "repeat " * 63 + "different\n",
    ]
    return TextScenario(
        "adversarial-near-miss-input",
        "adversarial",
        ScanScope.INPUT,
        _pad(parts, size, unit="ordinary multilingual café 数据 line\n"),
    )


def _dense_input(size: int) -> TextScenario:
    parts: list[str] = []
    expected: list[ExpectedFinding] = []
    for index in range(64):
        _append(
            parts,
            expected,
            "content.banned_substrings",
            BANNED_MARKER,
            prefix=f"literal_case_{index:03d}: ",
        )
    for index in range(64):
        _append(
            parts,
            expected,
            "pii.payment_card",
            "4242424242424242",
            prefix=f"card_case_{index:03d}: ",
        )
    return TextScenario(
        "dense-input",
        "dense",
        ScanScope.INPUT,
        _pad(parts, size, unit="dense profile safe tail"),
        tuple(expected),
    )


def _clean_input(size: int) -> TextScenario:
    return TextScenario(
        "clean-input",
        "clean",
        ScanScope.INPUT,
        _pad([], size, unit="ordinary enterprise report line with status green\n"),
    )


def _clean_code_log_input(size: int) -> TextScenario:
    parts: list[str] = []
    current = 0
    index = 0
    templates = (
        "INFO request={index:08d} status=green duration_ms=12\n",
        "value_{index:08d} = transform(source_{index:08d})\n",
        "ordinary multilingual café 数据 नमस्ते record {index:08d}\n",
    )
    while current < size:
        line = templates[index % len(templates)].format(index=index)
        fragment = line[: size - current]
        parts.append(fragment)
        current += len(fragment)
        index += 1
    return TextScenario(
        "clean-code-log-input",
        "clean",
        ScanScope.INPUT,
        "".join(parts),
    )


def _clean_output(size: int) -> TextScenario:
    prefix = '{"message":"'
    suffix = '"}'
    if size < len(prefix) + len(suffix):
        raise ValueError("size is too small for a valid JSON output")
    target = size - len(prefix) - len(suffix)
    chunks: list[str] = []
    current = 0
    index = 0
    while current < target:
        chunk = f"ordinary generated response item {index:08d} "
        fragment = chunk[: target - current]
        chunks.append(fragment)
        current += len(fragment)
        index += 1
    payload = "".join(chunks)
    text = prefix + payload + suffix
    json.loads(text)  # Defensive generator invariant.
    return TextScenario("clean-output-json", "clean", ScanScope.OUTPUT, text)


def _invalid_output(size: int) -> TextScenario:
    text = _pad(["not-json\n"], size, unit="ordinary invalid output field")
    return TextScenario(
        "invalid-output-json",
        "sparse",
        ScanScope.OUTPUT,
        text,
        (ExpectedFinding("output.json.validity", 0, 1, "block"),),
    )


def build_text_scenarios(size: int) -> tuple[TextScenario, ...]:
    """Build exact-size clean, positive, and adversarial text profiles."""

    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise ValueError("size must be a positive integer")
    return (
        _clean_input(size),
        _clean_code_log_input(size),
        _clean_output(size),
        _invalid_output(size),
        _positive_input(size),
        _dense_input(size),
        _near_miss_input(size),
    )


def build_structured_scenarios() -> StructuredScenarios:
    """Build deterministic tool-call and tool-result validation cases."""

    definition = ToolDefinition(
        "lookup",
        {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
    )
    valid_call = ToolCall("lookup", {"query": "synthetic benchmark"}, "call-1")
    invalid_call = ToolCall("undeclared", {"query": "synthetic benchmark"}, "call-2")
    valid_result = ToolResultBatch(
        (valid_call,),
        (ToolResult("call-1", "synthetic benchmark result", "lookup"),),
    )
    invalid_result = ToolResultBatch(
        (valid_call,),
        (ToolResult("unmatched-call", "synthetic benchmark result", "lookup"),),
    )
    return StructuredScenarios(
        definition, valid_call, invalid_call, valid_result, invalid_result
    )


def manifest(scenarios: tuple[TextScenario, ...]) -> dict[str, object]:
    """Return a compact manifest that never retains corpus or matched values."""

    return {
        "schema_version": 1,
        "generator": "deterministic-local-all-rules",
        "uses_llm": False,
        "uses_network": False,
        "uses_randomness": False,
        "structured_scenarios": {
            "tool_call": ["valid", "undeclared_tool"],
            "tool_result": ["valid", "unmatched_call_id"],
        },
        "scenarios": [
            {
                "scenario_id": scenario.scenario_id,
                "profile": scenario.profile,
                "scope": scenario.scope.value,
                "characters": len(scenario.text),
                "utf8_bytes": len(scenario.text.encode("utf-8")),
                "sha256": scenario.sha256,
                "expected_findings": [
                    {
                        "rule_id": item.rule_id,
                        "action": item.action,
                        "span": {"start": item.start, "end": item.end},
                    }
                    for item in scenario.expected
                ],
            }
            for scenario in scenarios
        ],
    }


__all__ = [
    "ALL_TEXT_RULE_IDS",
    "BANNED_MARKER",
    "ExpectedFinding",
    "StructuredScenarios",
    "TextScenario",
    "build_structured_scenarios",
    "build_text_scenarios",
    "manifest",
]
