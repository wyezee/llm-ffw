import random
import time
import unittest

import llm_ffw
from benchmarks.synthetic_data import synthetic_token
from llm_ffw import (
    Action,
    AUDIT_POLICY,
    BALANCED_POLICY,
    BUILTIN_SECRET_CATALOG,
    ContentBlockedError,
    Firewall,
    FirewallStream,
    FirewallStreamState,
    IncrementalStreamingUnavailableError,
    ScanScope,
    Scanner,
    ScannerConfig,
    SecretCatalog,
    SecretSignature,
    Severity,
    STRICT_POLICY,
    StreamingSupport,
    StreamMode,
)
from llm_ffw.rules import InvisibleCharactersRule, SecretsRule


def _custom_catalog(
    *,
    action: Action = Action.REDACT,
    max_suffix_chars: int | None = 16,
    suffix_ending: str = "",
    boundary_chars: str = "ACME_B012",
) -> SecretCatalog:
    return SecretCatalog(
        catalog_id="streaming.custom.secrets",
        version="1.0.0",
        signatures=(
            SecretSignature(
                signature_id="acme.streaming_token",
                provider="acme",
                secret_type="streaming_token",
                prefixes=("ACME_",),
                suffix_chars="ACME_B012",
                min_suffix_chars=8,
                max_suffix_chars=max_suffix_chars,
                boundary_chars=boundary_chars,
                source="internal://security/streaming-token",
                severity=Severity.HIGH,
                action=action,
                suffix_ending=suffix_ending,
            ),
        ),
    )


def _secret_scanner(
    max_input_chars: int,
    *,
    catalog: SecretCatalog = BUILTIN_SECRET_CATALOG,
    redaction_text: str = "[REDACTED]",
) -> Scanner:
    return Scanner(
        rules=(SecretsRule(catalog),),
        config=ScannerConfig(
            max_input_chars=max_input_chars,
            redaction_text=redaction_text,
        ),
    )


def _oracle(
    text: str,
    *,
    catalog: SecretCatalog = BUILTIN_SECRET_CATALOG,
    policy=BALANCED_POLICY,
):
    return Firewall(
        scanner=_secret_scanner(max(1, len(text)), catalog=catalog),
        policy=policy,
    ).process(text, scope=ScanScope.INPUT)


def _run_incremental(
    text: str,
    chunks: tuple[str, ...],
    *,
    catalog: SecretCatalog = BUILTIN_SECRET_CATALOG,
    policy=BALANCED_POLICY,
    redaction_text: str = "[REDACTED]",
) -> tuple[str, FirewallStream]:
    stream = FirewallStream(
        scanner=_secret_scanner(
            max(1, len(text)),
            catalog=catalog,
            redaction_text=redaction_text,
        ),
        policy=policy,
        mode=StreamMode.INCREMENTAL,
    )
    parts = [stream.feed(chunk) for chunk in chunks]
    parts.append(stream.finish())
    return "".join(parts), stream


class FirewallStreamContractTests(unittest.TestCase):
    def test_rule_specific_stream_is_not_a_public_api(self) -> None:
        self.assertFalse(hasattr(llm_ffw, "SecretStream"))

    def test_default_auto_preserves_all_rules_by_buffering(self) -> None:
        text = "before sk-" + "A" * 20 + " after"
        firewall = Firewall()
        oracle = firewall.process(text, scope=ScanScope.INPUT)
        stream = FirewallStream()

        self.assertEqual(stream.requested_mode, StreamMode.AUTO)
        self.assertEqual(stream.execution_mode, StreamMode.BUFFERED)
        self.assertEqual(stream.policy_id, BALANCED_POLICY.policy_id)
        self.assertEqual(stream.policy_version, BALANCED_POLICY.version)
        self.assertEqual(stream.feed(text[:10]), "")
        self.assertEqual(stream.feed(text[10:]), "")
        self.assertEqual(stream.buffered_chars, len(text))
        self.assertEqual(stream.finish(), oracle.processed_text)
        self.assertEqual(stream.findings, oracle.findings)
        self.assertEqual(stream.decision, oracle.decision)
        self.assertEqual(stream.buffered_chars, 0)

        capabilities = {
            item.rule_id: item.support for item in stream.rule_capabilities
        }
        self.assertEqual(
            capabilities[SecretsRule.RULE_ID],
            StreamingSupport.INCREMENTAL,
        )
        self.assertEqual(
            capabilities[InvisibleCharactersRule.RULE_ID],
            StreamingSupport.END_OF_STREAM,
        )

    def test_explicit_incremental_rejects_incompatible_active_rules(self) -> None:
        with self.assertRaises(IncrementalStreamingUnavailableError) as caught:
            FirewallStream(mode=StreamMode.INCREMENTAL)
        self.assertIn(
            InvisibleCharactersRule.RULE_ID,
            caught.exception.incompatibilities,
        )
        self.assertNotIn(
            SecretsRule.RULE_ID,
            caught.exception.incompatibilities,
        )

    def test_firewall_factory_uses_existing_scanner_and_policy(self) -> None:
        scanner = _secret_scanner(128)
        firewall = Firewall(scanner=scanner, policy=BALANCED_POLICY)
        stream = firewall.stream(mode=StreamMode.INCREMENTAL)
        self.assertEqual(stream.execution_mode, StreamMode.INCREMENTAL)
        output = stream.feed("sk-" + "A" * 20) + stream.finish()
        self.assertEqual(output, "[REDACTED]")

    def test_rules_inactive_for_scope_do_not_prevent_incremental_mode(self) -> None:
        scanner = Scanner(
            rules=(SecretsRule(), InvisibleCharactersRule()),
            config=ScannerConfig(max_input_chars=128),
        )
        stream = FirewallStream(
            scanner=scanner,
            scope=ScanScope.OUTPUT,
            mode=StreamMode.INCREMENTAL,
        )
        self.assertEqual(stream.execution_mode, StreamMode.INCREMENTAL)
        self.assertEqual(
            tuple(item.rule_id for item in stream.rule_capabilities),
            (SecretsRule.RULE_ID,),
        )

    def test_incremental_output_preserves_scope_and_prompt_context_contract(
        self,
    ) -> None:
        text = "sk-" + "A" * 20
        context = "private prompt context"
        scanner = _secret_scanner(128)
        oracle = Firewall(scanner=scanner).process(
            text,
            scope=ScanScope.OUTPUT,
            prompt_context=context,
        )
        stream = FirewallStream(
            scanner=scanner,
            scope=ScanScope.OUTPUT,
            mode=StreamMode.INCREMENTAL,
            prompt_context=context,
        )
        streamed = stream.feed(text) + stream.finish()
        self.assertEqual(streamed, oracle.processed_text)
        self.assertEqual(stream.findings, oracle.findings)
        self.assertIsNone(stream._prompt_context)

    def test_no_active_rules_emit_unchanged_chunks_incrementally(self) -> None:
        stream = FirewallStream(
            scanner=Scanner(rules=()),
            mode=StreamMode.INCREMENTAL,
        )
        self.assertEqual(stream.feed("safe"), "safe")
        self.assertEqual(stream.finish(), "")
        self.assertEqual(stream.decision, Action.ALLOW)
        self.assertEqual(stream.findings, ())

    def test_custom_scanner_implementations_require_buffered_execution(self) -> None:
        class CustomScanner(Scanner):
            pass

        scanner = CustomScanner(rules=())
        automatic = FirewallStream(scanner=scanner)
        self.assertEqual(automatic.execution_mode, StreamMode.BUFFERED)
        with self.assertRaises(IncrementalStreamingUnavailableError) as caught:
            FirewallStream(
                scanner=scanner,
                mode=StreamMode.INCREMENTAL,
            )
        self.assertEqual(
            caught.exception.incompatibilities,
            ("scanner.custom",),
        )

    def test_policy_that_can_block_forces_buffered_or_rejects(self) -> None:
        scanner = _secret_scanner(128)
        automatic = FirewallStream(
            scanner=scanner,
            policy=STRICT_POLICY,
        )
        self.assertEqual(automatic.execution_mode, StreamMode.BUFFERED)
        self.assertEqual(
            automatic.rule_capabilities[0].support,
            StreamingSupport.END_OF_STREAM,
        )
        automatic.feed("sk-" + "A" * 20)
        with self.assertRaises(ContentBlockedError):
            automatic.finish()
        self.assertEqual(automatic.state, FirewallStreamState.FINISHED)
        self.assertEqual(automatic.decision, Action.BLOCK)

        with self.assertRaises(IncrementalStreamingUnavailableError) as caught:
            FirewallStream(
                scanner=scanner,
                policy=STRICT_POLICY,
                mode=StreamMode.INCREMENTAL,
            )
        self.assertEqual(
            caught.exception.incompatibilities,
            (SecretsRule.RULE_ID,),
        )

    def test_audit_policy_auto_buffers_and_preserves_original_text(self) -> None:
        text = "sk-" + "A" * 20
        stream = FirewallStream(
            scanner=_secret_scanner(128),
            policy=AUDIT_POLICY,
        )
        self.assertEqual(stream.execution_mode, StreamMode.BUFFERED)
        self.assertEqual(stream.feed(text), "")
        self.assertEqual(stream.finish(), text)
        self.assertEqual(stream.decision, Action.REVIEW)

    def test_explicit_buffered_mode_never_emits_early(self) -> None:
        text = "safe text"
        stream = FirewallStream(
            scanner=Scanner(rules=()),
            mode=StreamMode.BUFFERED,
        )
        self.assertEqual(stream.feed(text), "")
        self.assertEqual(stream.finish(), text)

    def test_buffered_output_preserves_prompt_context_contract(self) -> None:
        text = "safe output"
        context = "private prompt context"
        firewall = Firewall()
        oracle = firewall.process(
            text,
            scope=ScanScope.OUTPUT,
            prompt_context=context,
        )
        stream = firewall.stream(
            scope=ScanScope.OUTPUT,
            prompt_context=context,
        )
        self.assertNotIn(context, repr(stream))
        self.assertEqual(stream.feed(text), "")
        self.assertEqual(stream.finish(), oracle.processed_text)
        self.assertEqual(stream.findings, oracle.findings)
        self.assertIsNone(stream._prompt_context)


class FirewallStreamParityTests(unittest.TestCase):
    def test_every_builtin_prefix_matches_batch_across_token_splits(self) -> None:
        for signature in BUILTIN_SECRET_CATALOG.signatures:
            for prefix in signature.prefixes:
                token = synthetic_token(signature, prefix)
                text = f"before {token} after"
                oracle = _oracle(text)
                token_start = len("before ")
                token_end = token_start + len(token)
                for split in range(token_start, token_end + 1):
                    with self.subTest(
                        signature=signature.signature_id,
                        prefix=prefix,
                        split=split,
                    ):
                        streamed, stream = _run_incremental(
                            text,
                            (text[:split], text[split:]),
                        )
                        self.assertEqual(streamed, oracle.processed_text)
                        self.assertEqual(stream.findings, oracle.findings)

    def test_multiple_candidates_crlf_and_small_chunks_match_batch(self) -> None:
        values = [
            synthetic_token(signature, signature.prefixes[0])
            for signature in BUILTIN_SECRET_CATALOG.signatures[:12]
        ]
        text = "\r\nsafe boundary\r\n".join(values)
        chunks = tuple(text[index : index + 7] for index in range(0, len(text), 7))
        oracle = _oracle(text)
        streamed, stream = _run_incremental(text, chunks)
        self.assertEqual(streamed, oracle.processed_text)
        self.assertEqual(stream.findings, oracle.findings)

    def test_candidate_overflow_matches_batch_redaction(self) -> None:
        token = "sk-" + "D" * 20 + " "
        text = token * 129
        oracle = _oracle(text)
        streamed, stream = _run_incremental(
            text,
            tuple(token for _ in range(129)),
        )
        self.assertEqual(streamed, oracle.processed_text)
        self.assertEqual(stream.findings, oracle.findings)
        self.assertEqual(
            stream.findings[-1].metadata["reason"],
            "candidate_limit_exceeded",
        )

    def test_seeded_random_chunk_plans_match_batch(self) -> None:
        generator = random.Random(2_026_08_16)
        tokens = tuple(
            synthetic_token(signature, prefix)
            for signature in BUILTIN_SECRET_CATALOG.signatures
            for prefix in signature.prefixes
        )
        noise = (
            "plain",
            "s",
            "sk",
            "sk-",
            "ask-",
            "\r\n",
            " boundary ",
            "xoxb-",
        )
        for case in range(500):
            text = "".join(
                generator.choice(tokens)
                if generator.random() < 0.25
                else generator.choice(noise)
                for _ in range(generator.randint(1, 20))
            )
            chunks: list[str] = []
            position = 0
            while position < len(text):
                width = generator.randint(1, 29)
                chunks.append(text[position : position + width])
                position += width
            oracle = _oracle(text)
            streamed, stream = _run_incremental(text, tuple(chunks))
            with self.subTest(case=case):
                self.assertEqual(streamed, oracle.processed_text)
                self.assertEqual(stream.findings, oracle.findings)


class FirewallStreamLifecycleTests(unittest.TestCase):
    def test_incremental_stream_emits_safe_text_and_redacts_early(self) -> None:
        stream = FirewallStream(
            scanner=_secret_scanner(128),
            mode=StreamMode.INCREMENTAL,
        )
        self.assertEqual(stream.feed("safe prefix "), "safe prefix ")
        self.assertEqual(stream.feed("sk-" + "A" * 20), "[REDACTED]")
        self.assertEqual(stream.buffered_chars, 0)
        self.assertEqual(stream.feed(" boundary"), " boundary")
        self.assertEqual(stream.finish(), "")
        self.assertEqual(stream.state, FirewallStreamState.FINISHED)
        self.assertEqual(stream.received_chars, 44)
        self.assertEqual(len(stream.findings), 1)

    def test_empty_stream_finishes_cleanly(self) -> None:
        stream = FirewallStream(
            scanner=_secret_scanner(1),
            mode=StreamMode.INCREMENTAL,
        )
        self.assertEqual(stream.finish(), "")
        self.assertEqual(stream.findings, ())
        self.assertEqual(stream.state, FirewallStreamState.FINISHED)

    def test_partial_prefix_is_held_until_resolved(self) -> None:
        stream = FirewallStream(
            scanner=_secret_scanner(128),
            mode=StreamMode.INCREMENTAL,
        )
        self.assertEqual(stream.feed("safe s"), "safe ")
        self.assertEqual(stream.buffered_chars, 1)
        self.assertEqual(stream.feed("k-" + "A" * 20), "[REDACTED]")
        self.assertEqual(stream.finish(), "")

    def test_long_candidate_retains_only_chunk_sized_text(self) -> None:
        text = "safe " + "sk-" + "A" * 262_144
        stream = FirewallStream(
            scanner=_secret_scanner(len(text)),
            mode=StreamMode.INCREMENTAL,
        )
        parts = []
        started = time.perf_counter()
        for index in range(0, len(text), 4_096):
            parts.append(stream.feed(text[index : index + 4_096]))
        parts.append(stream.finish())
        elapsed = time.perf_counter() - started
        self.assertEqual("".join(parts), "safe [REDACTED]")
        self.assertLessEqual(stream.max_buffered_chars, 4_096)
        self.assertEqual(stream.buffered_chars, 0)
        self.assertLess(elapsed, 1.0)

    def test_limit_failure_cancels_and_releases_source_text(self) -> None:
        stream = FirewallStream(
            scanner=_secret_scanner(8),
            mode=StreamMode.INCREMENTAL,
        )
        stream.feed("sk-")
        with self.assertRaisesRegex(ValueError, "max_input_chars"):
            stream.feed("A" * 6)
        self.assertEqual(stream.state, FirewallStreamState.CANCELLED)
        self.assertEqual(stream.buffered_chars, 0)

        buffered = FirewallStream(
            scanner=Scanner(
                rules=(),
                config=ScannerConfig(max_input_chars=8),
            ),
            mode=StreamMode.BUFFERED,
        )
        buffered.feed("private")
        with self.assertRaisesRegex(ValueError, "max_input_chars"):
            buffered.feed("xx")
        self.assertEqual(buffered.buffered_chars, 0)

    def test_cancel_and_finish_are_terminal(self) -> None:
        cancelled = FirewallStream(scanner=Scanner(rules=()))
        cancelled.feed("safe")
        cancelled.cancel()
        cancelled.cancel()
        with self.assertRaisesRegex(RuntimeError, "not open"):
            cancelled.feed("again")
        with self.assertRaisesRegex(RuntimeError, "not open"):
            cancelled.finish()

        finished = FirewallStream(scanner=Scanner(rules=()))
        finished.finish()
        with self.assertRaisesRegex(RuntimeError, "not open"):
            finished.feed("again")

    def test_repr_does_not_disclose_buffered_or_candidate_text(self) -> None:
        value = "ACME_ABC012AB"
        catalog = _custom_catalog()
        incremental = FirewallStream(
            scanner=_secret_scanner(64, catalog=catalog),
            mode=StreamMode.INCREMENTAL,
        )
        incremental.feed(value)
        self.assertNotIn(value, repr(incremental))
        self.assertFalse(hasattr(incremental, "__dict__"))
        incremental.cancel()

        buffered = FirewallStream(mode=StreamMode.BUFFERED)
        buffered.feed(value)
        self.assertNotIn(value, repr(buffered))
        buffered.cancel()


class FirewallStreamConfigurationTests(unittest.TestCase):
    def test_balanced_policy_can_redact_block_recommending_catalog(self) -> None:
        catalog = _custom_catalog(action=Action.BLOCK)
        text = "ACME_ABC012AB"
        oracle = _oracle(text, catalog=catalog)
        streamed, stream = _run_incremental(text, (text,), catalog=catalog)
        self.assertEqual(streamed, oracle.processed_text)
        self.assertEqual(stream.findings, oracle.findings)
        self.assertEqual(stream.decision, Action.REDACT)

    def test_unsafe_candidate_shapes_auto_buffer_or_explicitly_reject(self) -> None:
        catalogs = (
            _custom_catalog(max_suffix_chars=None, suffix_ending="A"),
            _custom_catalog(
                max_suffix_chars=None,
                boundary_chars="ACME_B012X",
            ),
            _custom_catalog(max_suffix_chars=65_537),
        )
        for catalog in catalogs:
            scanner = _secret_scanner(128, catalog=catalog)
            with self.subTest(catalog=catalog):
                automatic = FirewallStream(scanner=scanner)
                self.assertEqual(
                    automatic.execution_mode,
                    StreamMode.BUFFERED,
                )
                self.assertEqual(
                    automatic.rule_capabilities[0].support,
                    StreamingSupport.END_OF_STREAM,
                )
                with self.assertRaises(IncrementalStreamingUnavailableError):
                    FirewallStream(
                        scanner=scanner,
                        mode=StreamMode.INCREMENTAL,
                    )

    def test_custom_redaction_text_is_used_without_changing_findings(self) -> None:
        text = "sk-" + "A" * 20
        streamed, stream = _run_incremental(
            text,
            (text,),
            redaction_text="<secret>",
        )
        self.assertEqual(streamed, "<secret>")
        self.assertEqual(
            stream.findings[0].redacted_preview,
            "[REDACTED:openai_api_key]",
        )

    def test_validates_modes_scope_context_and_chunks(self) -> None:
        with self.assertRaises(TypeError):
            FirewallStream(scanner=object())
        with self.assertRaises(TypeError):
            FirewallStream(policy=object())
        with self.assertRaises(TypeError):
            FirewallStream(scope="input")
        with self.assertRaises(TypeError):
            FirewallStream(mode="auto")
        with self.assertRaises(ValueError):
            FirewallStream(prompt_context="not valid for input")
        with self.assertRaises(TypeError):
            FirewallStream(
                scope=ScanScope.OUTPUT,
                prompt_context=object(),
            )

        stream = FirewallStream(scanner=Scanner(rules=()))
        with self.assertRaises(TypeError):
            stream.feed(object())
        with self.assertRaises(ValueError):
            stream.feed("")
        self.assertEqual(stream.state, FirewallStreamState.OPEN)


if __name__ == "__main__":
    unittest.main()
