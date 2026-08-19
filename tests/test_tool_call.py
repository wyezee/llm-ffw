import time
import unittest

from llm_ffw import (
    Action,
    EmailAddressRule,
    RuleScanner,
    ScanScope,
    ToolCall,
    ToolCallBlockedError,
    ToolCallConfig,
    ToolCallRule,
    ToolDefinition,
)


def _weather_definition() -> ToolDefinition:
    return ToolDefinition(
        name="get_weather",
        parameters={
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "units": {
                    "type": "string",
                    "enum": ["celsius", "fahrenheit"],
                },
                "days": {"type": "integer"},
            },
            "required": ["city"],
            "additionalProperties": False,
        },
    )


class ToolCallDataTests(unittest.TestCase):
    def test_copies_arguments_and_schema_into_immutable_trees(self) -> None:
        arguments = {"city": "Pune", "nested": [1, 2]}
        call = ToolCall("get_weather", arguments, "call:1")
        arguments["city"] = "changed"
        arguments["nested"].append(3)
        self.assertEqual(call.arguments["city"], "Pune")  # type: ignore[index]
        self.assertEqual(call.arguments["nested"], (1, 2))  # type: ignore[index]
        self.assertNotIn("Pune", repr(call))
        self.assertNotIn("call:1", repr(call))
        with self.assertRaises(TypeError):
            call.arguments["city"] = "changed"  # type: ignore[index]

    def test_rejects_non_json_values_and_non_finite_numbers(self) -> None:
        for arguments in (
            {"bad": object()},
            {"bad": float("nan")},
            {1: "bad"},
        ):
            with self.subTest(arguments=arguments), self.assertRaises(
                (TypeError, ValueError)
            ):
                ToolCall("tool", arguments)  # type: ignore[arg-type]

    def test_rejects_invalid_names_ids_and_limits(self) -> None:
        for name in ("", "white space", "é"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                ToolCall(name)
        with self.assertRaises(ValueError):
            ToolCall("tool", call_id="contains space")
        with self.assertRaises(TypeError):
            ToolCallConfig(max_nodes=True)
        with self.assertRaises(ValueError):
            ToolCallConfig(max_depth=65)
        with self.assertRaises(TypeError):
            ToolCallConfig(inspect_content="yes")  # type: ignore[arg-type]


class ToolCallRuleTests(unittest.TestCase):
    def test_default_content_inspection_blocks_secret_values_and_keys(self) -> None:
        secret = "sk-" + "A" * 20
        rule = ToolCallRule(
            (
                ToolDefinition(
                    "open",
                    {"type": "object", "additionalProperties": True},
                ),
            )
        )
        for arguments in ({"value": secret}, {secret: "value"}):
            with self.subTest(arguments=tuple(arguments)):
                finding = rule.validate(ToolCall("open", arguments))[0]
                self.assertEqual(
                    finding.metadata["reason"],
                    "content_policy_violation",
                )
                self.assertEqual(
                    finding.metadata["content_rule_id"],
                    "secrets.detected",
                )
                self.assertEqual(finding.metadata["content_action"], "redact")
                self.assertNotIn(secret, repr(finding))

    def test_content_inspection_uses_outbound_scope_and_can_be_disabled(self) -> None:
        definition = ToolDefinition(
            "open",
            {"type": "object", "additionalProperties": True},
        )
        email = "customer@example.com"
        email_scanner = RuleScanner(rules=(EmailAddressRule(),))
        outbound = ToolCallRule(
            (definition,),
            content_scanner=email_scanner,
        )
        self.assertEqual(
            outbound.validate(ToolCall("open", {"value": email})),
            (),
        )
        disabled = ToolCallRule(
            (definition,),
            ToolCallConfig(inspect_content=False),
        )
        self.assertEqual(
            disabled.validate(
                ToolCall("open", {"value": "sk-" + "A" * 20})
            ),
            (),
        )
        with self.assertRaises(ValueError):
            ToolCallRule(
                (definition,),
                ToolCallConfig(inspect_content=False),
                content_scanner=email_scanner,
            )
        with self.assertRaises(TypeError):
            ToolCallRule((definition,), content_scanner=object())  # type: ignore[arg-type]

    def test_accepts_declared_call_with_valid_typed_arguments(self) -> None:
        rule = ToolCallRule((_weather_definition(),))
        self.assertEqual(
            rule.validate(
                ToolCall(
                    "get_weather",
                    {"city": "Pune", "units": "celsius", "days": 2},
                )
            ),
            (),
        )
        self.assertEqual(rule.scopes, frozenset((ScanScope.TOOL_CALL,)))

    def test_blocks_unknown_tool_without_disclosing_its_name(self) -> None:
        unknown = "private_internal_operation"
        finding = ToolCallRule((_weather_definition(),)).validate(
            ToolCall(unknown, {})
        )[0]
        self.assertIs(finding.action, Action.BLOCK)
        self.assertEqual(finding.rule_id, "tools.call.validity")
        self.assertEqual(finding.metadata["reason"], "tool_not_allowed")
        self.assertEqual(finding.metadata["span_basis"], "structured")
        self.assertEqual((finding.span.start, finding.span.end), (0, 0))
        self.assertNotIn(unknown, finding.message)
        self.assertNotIn(unknown, repr(finding))

    def test_enforce_returns_valid_call_and_raises_disclosure_safe_error(self) -> None:
        rule = ToolCallRule((_weather_definition(),))
        valid = ToolCall("get_weather", {"city": "Pune"})
        self.assertIs(rule.enforce(valid), valid)
        secret = "customer-secret-key"
        with self.assertRaises(ToolCallBlockedError) as raised:
            rule.enforce(ToolCall("get_weather", {secret: "sensitive"}))
        self.assertNotIn(secret, repr(raised.exception))
        self.assertNotIn("sensitive", repr(raised.exception))
        self.assertEqual(
            raised.exception.findings[0].metadata["location"],
            "arguments",
        )

    def test_blocks_missing_wrong_enum_and_additional_arguments(self) -> None:
        rule = ToolCallRule((_weather_definition(),))
        cases = (
            ({}, "required_property_missing"),
            ({"city": 7}, "type_mismatch"),
            ({"city": "Pune", "units": "kelvin"}, "enum_mismatch"),
            ({"city": "Pune", "admin": True}, "additional_property_forbidden"),
        )
        for arguments, reason in cases:
            with self.subTest(reason=reason):
                finding = rule.validate(ToolCall("get_weather", arguments))[0]
                self.assertEqual(finding.metadata["reason"], reason)

    def test_no_argument_tool_rejects_arguments(self) -> None:
        rule = ToolCallRule((ToolDefinition("ping"),))
        self.assertEqual(rule.validate(ToolCall("ping")), ())
        for arguments in ({}, {"value": 1}):
            with self.subTest(arguments=arguments):
                finding = rule.validate(ToolCall("ping", arguments))[0]
                self.assertEqual(
                    finding.metadata["reason"], "arguments_not_allowed"
                )

    def test_all_supported_schema_types_and_nested_arrays(self) -> None:
        definition = ToolDefinition(
            "typed",
            {
                "type": "object",
                "properties": {
                    "array": {"type": "array", "items": {"type": "boolean"}},
                    "number": {"type": "number"},
                    "nothing": {"type": "null"},
                },
                "required": ["array", "number", "nothing"],
                "additionalProperties": False,
            },
        )
        rule = ToolCallRule((definition,))
        self.assertEqual(
            rule.validate(
                ToolCall(
                    "typed",
                    {
                        "array": [True, False],
                        "number": 1.5,
                        "nothing": None,
                    },
                )
            ),
            (),
        )

    def test_schema_rejects_unsupported_or_ambiguous_constructs(self) -> None:
        schemas = (
            {"properties": {}},
            {"type": ["string", "null"]},
            {"type": "string", "pattern": ".*"},
            {"type": "array"},
            {"type": "object", "required": ["missing"]},
            {"type": "object", "properties": {}},
            {"type": "object", "additionalProperties": {}},
            {"type": "string", "enum": [1]},
            {"type": "object", "enum": [None]},
        )
        for schema in schemas:
            with self.subTest(schema=schema), self.assertRaises(
                (TypeError, ValueError)
            ):
                ToolCallRule((ToolDefinition("tool", schema),))

    def test_resource_limits_include_allowed_additional_properties(self) -> None:
        rule = ToolCallRule(
            (
                ToolDefinition(
                    "tool",
                    {"type": "object", "additionalProperties": True},
                ),
            ),
            ToolCallConfig(max_nodes=3, max_total_string_chars=100),
        )
        sensitive_key = "s3cr3t-leaf-key"
        finding = rule.validate(
            ToolCall("tool", {"x": {"y": {sensitive_key: 1}}})
        )[0]
        self.assertEqual(finding.metadata["reason"], "node_limit_exceeded")
        self.assertNotIn(sensitive_key, repr(finding))

    def test_large_adversarial_call_is_bounded_and_fails_closed(self) -> None:
        rule = ToolCallRule(
            (
                ToolDefinition(
                    "batch",
                    {
                        "type": "object",
                        "properties": {
                            "values": {
                                "type": "array",
                                "items": {"type": "integer"},
                            }
                        },
                        "required": ["values"],
                        "additionalProperties": False,
                    },
                ),
            ),
            ToolCallConfig(max_nodes=1_000, max_array_items=10_000),
        )
        call = ToolCall("batch", {"values": list(range(10_000))})
        started = time.perf_counter()
        finding = rule.validate(call)[0]
        elapsed = time.perf_counter() - started
        self.assertEqual(finding.metadata["reason"], "node_limit_exceeded")
        self.assertLess(elapsed, 0.1)


if __name__ == "__main__":
    unittest.main()
