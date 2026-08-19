import time
import unittest

from llm_ffw import (
    Action,
    EmailAddressRule,
    RuleScanner,
    ScanScope,
    ToolCall,
    ToolResult,
    ToolResultBatch,
    ToolResultBlockedError,
    ToolResultConfig,
    ToolResultRule,
)


def _call(call_id: str | None = "call-1", name: str = "get_weather") -> ToolCall:
    return ToolCall(name, {"city": "Pune"}, call_id)


def _result(
    call_id: str | None = "call-1",
    name: str | None = "get_weather",
    content: object = "sunny",
) -> ToolResult:
    return ToolResult(call_id, content, name)  # type: ignore[arg-type]


class ToolResultDataTests(unittest.TestCase):
    def test_copies_blocks_into_immutable_disclosure_safe_result(self) -> None:
        blocks = [{"type": "text", "text": "sensitive output"}]
        result = _result(content=blocks)
        blocks[0]["text"] = "changed"
        self.assertEqual(result.content[0]["text"], "sensitive output")
        self.assertNotIn("sensitive", repr(result))
        self.assertNotIn("call-1", repr(result))
        self.assertNotIn("get_weather", repr(result))
        with self.assertRaises(TypeError):
            result.content[0]["text"] = "changed"

    def test_rejects_invalid_content_shape_and_json_values(self) -> None:
        values = (
            7,
            ["not-an-object"],
            [{"bad": object()}],
            [{1: "bad-key"}],
        )
        for value in values:
            with self.subTest(value=value), self.assertRaises(
                (TypeError, ValueError)
            ):
                _result(content=value)

    def test_batch_is_nonempty_bounded_and_typed(self) -> None:
        with self.assertRaises(ValueError):
            ToolResultBatch((), ())
        with self.assertRaises(TypeError):
            ToolResultBatch((object(),), (_result(),))  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            ToolResultBatch((_call(),), (object(),))  # type: ignore[arg-type]

    def test_rejects_invalid_config_limits(self) -> None:
        with self.assertRaises(TypeError):
            ToolResultConfig(max_results=True)
        with self.assertRaises(ValueError):
            ToolResultConfig(max_results=0)
        with self.assertRaises(ValueError):
            ToolResultConfig(max_depth=65)
        with self.assertRaises(TypeError):
            ToolResultConfig(inspect_content="yes")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            ToolResult("call", "value", limits=object())  # type: ignore[arg-type]

    def test_construction_enforces_per_result_and_aggregate_budgets(self) -> None:
        with self.assertRaisesRegex(ValueError, "too much string data"):
            ToolResult("call", "x" * 100_001)
        first = ToolResult("call-1", "x" * 60_000, "tool")
        second = ToolResult("call-2", "y" * 60_000, "tool")
        calls = (
            ToolCall("tool", call_id="call-1"),
            ToolCall("tool", call_id="call-2"),
        )
        with self.assertRaisesRegex(ValueError, "string_limit_exceeded"):
            ToolResultBatch(calls, (first, second))


class ToolResultRuleTests(unittest.TestCase):
    def test_builders_apply_one_config_to_results_and_batches(self) -> None:
        config = ToolResultConfig(max_total_string_chars=20)
        rule = ToolResultRule(config)
        result = rule.build_result("call-1", "safe", "get_weather")
        batch = rule.build_batch((_call(),), (result,))
        self.assertIs(result.limits, config)
        self.assertIs(batch.limits, config)
        self.assertIs(rule.enforce(batch), batch)
        with self.assertRaisesRegex(ValueError, "too much string data"):
            rule.build_result("call-1", "x" * 21, "get_weather")

    def test_default_content_inspection_blocks_secret_values_and_keys(self) -> None:
        secret = "sk-" + "B" * 20
        rule = ToolResultRule()
        for content in (secret, [{secret: "value"}]):
            with self.subTest(content_type=type(content).__name__):
                batch = ToolResultBatch(
                    (_call(),),
                    (_result(content=content),),
                )
                finding = rule.validate(batch)[0]
                self.assertEqual(
                    finding.metadata["reason"],
                    "content_policy_violation",
                )
                self.assertEqual(
                    finding.metadata["content_rule_id"],
                    "secrets.detected",
                )
                self.assertNotIn(secret, repr(finding))

    def test_content_inspection_uses_inbound_scope_and_can_be_disabled(self) -> None:
        email = "customer@example.com"
        scanner = RuleScanner(rules=(EmailAddressRule(),))
        batch = ToolResultBatch(
            (_call(),),
            (_result(content=email),),
        )
        finding = ToolResultRule(content_scanner=scanner).validate(batch)[0]
        self.assertEqual(finding.metadata["content_rule_id"], "pii.email_address")
        self.assertEqual(
            ToolResultRule(
                ToolResultConfig(inspect_content=False)
            ).validate(batch),
            (),
        )
        with self.assertRaises(ValueError):
            ToolResultRule(
                ToolResultConfig(inspect_content=False),
                content_scanner=scanner,
            )
        with self.assertRaises(TypeError):
            ToolResultRule(content_scanner=object())  # type: ignore[arg-type]

    def test_accepts_linked_string_and_content_block_results(self) -> None:
        batch = ToolResultBatch(
            (_call("call-1"), _call("call-2", "search")),
            (
                _result("call-1"),
                _result(
                    "call-2",
                    "search",
                    [
                        {"type": "text", "text": "answer"},
                        {
                            "type": "image",
                            "source": {"kind": "reference", "id": "asset-1"},
                        },
                    ],
                ),
            ),
        )
        rule = ToolResultRule()
        self.assertEqual(rule.validate(batch), ())
        self.assertIs(rule.enforce(batch), batch)
        self.assertEqual(rule.scopes, frozenset((ScanScope.TOOL_RESULT,)))

    def test_blocks_missing_duplicate_and_unmatched_linkage(self) -> None:
        cases = (
            (
                ToolResultBatch((_call(None),), (_result(),)),
                "expected_call_id_missing",
            ),
            (
                ToolResultBatch((_call(), _call()), (_result(),)),
                "expected_call_id_duplicate",
            ),
            (
                ToolResultBatch((_call(),), (_result(None),)),
                "result_call_id_missing",
            ),
            (
                ToolResultBatch((_call(),), (_result(), _result())),
                "result_call_id_duplicate",
            ),
            (
                ToolResultBatch((_call(),), (_result("other-call"),)),
                "result_call_id_unmatched",
            ),
        )
        rule = ToolResultRule()
        for batch, reason in cases:
            with self.subTest(reason=reason):
                finding = rule.validate(batch)[0]
                self.assertEqual(finding.metadata["reason"], reason)

    def test_blocks_missing_and_mismatched_tool_names(self) -> None:
        rule = ToolResultRule()
        cases = (
            (_result(name=None), "result_name_missing"),
            (_result(name="other_tool"), "result_name_mismatch"),
        )
        for result, reason in cases:
            with self.subTest(reason=reason):
                finding = rule.validate(
                    ToolResultBatch((_call(),), (result,))
                )[0]
                self.assertEqual(finding.metadata["reason"], reason)

    def test_findings_and_exception_do_not_disclose_dynamic_values(self) -> None:
        call_id = "private-call-id"
        name = "private_tool"
        content = "private tool output"
        batch = ToolResultBatch(
            (_call(call_id, name),),
            (_result("unmatched-id", name, content),),
        )
        rule = ToolResultRule()
        finding = rule.validate(batch)[0]
        self.assertIs(finding.action, Action.BLOCK)
        self.assertEqual(finding.rule_id, "tools.result.validity")
        self.assertEqual((finding.span.start, finding.span.end), (0, 0))
        for sensitive in (call_id, name, content, "unmatched-id"):
            self.assertNotIn(sensitive, repr(finding))
        with self.assertRaises(ToolResultBlockedError) as raised:
            rule.enforce(batch)
        for sensitive in (call_id, name, content, "unmatched-id"):
            self.assertNotIn(sensitive, repr(raised.exception))

    def test_configured_batch_and_content_limits_fail_closed(self) -> None:
        linked = ToolResultBatch((_call(),), (_result(),))
        result_limit = ToolResultRule(ToolResultConfig(max_results=1))
        duplicate_batch = ToolResultBatch(
            (_call("call-1"), _call("call-2")),
            (_result("call-1"), _result("call-2")),
        )
        finding = result_limit.validate(duplicate_batch)[0]
        self.assertEqual(finding.metadata["reason"], "result_limit_exceeded")

        string_limit = ToolResultRule(
            ToolResultConfig(max_total_string_chars=3)
        )
        finding = string_limit.validate(linked)[0]
        self.assertEqual(finding.metadata["reason"], "string_limit_exceeded")

        block_limit = ToolResultRule(ToolResultConfig(max_object_properties=1))
        block_batch = ToolResultBatch(
            (_call(),),
            (_result(content=[{"type": "text", "text": "value"}]),),
        )
        finding = block_limit.validate(block_batch)[0]
        self.assertEqual(finding.metadata["reason"], "object_limit_exceeded")

    def test_large_adversarial_content_is_bounded_and_fails_closed(self) -> None:
        blocks = [{"index": index} for index in range(10_000)]
        relaxed = ToolResultConfig(
            max_nodes=100_000,
            max_array_items=10_000,
        )
        batch = ToolResultBatch(
            (_call(),),
            (ToolResult("call-1", blocks, "get_weather", limits=relaxed),),
            limits=relaxed,
        )
        rule = ToolResultRule(
            ToolResultConfig(max_nodes=1_000, max_array_items=10_000)
        )
        started = time.perf_counter()
        finding = rule.validate(batch)[0]
        elapsed = time.perf_counter() - started
        self.assertEqual(finding.metadata["reason"], "node_limit_exceeded")
        self.assertLess(elapsed, 0.1)


if __name__ == "__main__":
    unittest.main()
