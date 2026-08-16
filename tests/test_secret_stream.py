import random
import time
import unittest

from benchmarks.synthetic_data import synthetic_token
from llm_ffw import (
    Action,
    BALANCED_POLICY,
    BUILTIN_SECRET_CATALOG,
    Firewall,
    ScanScope,
    Scanner,
    ScannerConfig,
    SecretCatalog,
    SecretSignature,
    SecretStream,
    SecretStreamState,
    Severity,
)
from llm_ffw.rules import SecretsRule


def _oracle(
    text: str,
    catalog: SecretCatalog = BUILTIN_SECRET_CATALOG,
):
    return Firewall(
        scanner=Scanner(
            rules=(SecretsRule(catalog),),
            config=ScannerConfig(max_input_chars=max(1, len(text))),
        ),
        policy=BALANCED_POLICY,
    ).process(text, scope=ScanScope.INPUT)


def _run_stream(
    text: str,
    chunks: tuple[str, ...],
    *,
    replacement_secret_catalog: SecretCatalog | None = None,
) -> tuple[str, SecretStream]:
    stream = SecretStream(
        replacement_secret_catalog=replacement_secret_catalog,
        max_input_chars=max(1, len(text)),
    )
    parts = [stream.feed(chunk) for chunk in chunks]
    parts.append(stream.finish())
    return "".join(parts), stream


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


class SecretStreamParityTests(unittest.TestCase):
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
                        streamed, stream = _run_stream(
                            text,
                            (text[:split], text[split:]),
                        )
                        self.assertEqual(streamed, oracle.processed_text)
                        self.assertEqual(stream.findings, oracle.findings)

    def test_multiple_candidates_crlf_and_small_chunks_match_batch(self) -> None:
        signatures = BUILTIN_SECRET_CATALOG.signatures[:12]
        values = [
            synthetic_token(signature, signature.prefixes[0])
            for signature in signatures
        ]
        text = "\r\nsafe boundary\r\n".join(values)
        chunks = tuple(text[index : index + 7] for index in range(0, len(text), 7))
        oracle = _oracle(text)
        streamed, stream = _run_stream(text, chunks)
        self.assertEqual(streamed, oracle.processed_text)
        self.assertEqual(stream.findings, oracle.findings)

    def test_candidate_overflow_matches_batch_fail_closed_redaction(self) -> None:
        token = "sk-" + "D" * 20 + " "
        text = token * 129
        oracle = _oracle(text)
        streamed, stream = _run_stream(text, tuple(token for _ in range(129)))
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
            streamed, stream = _run_stream(text, tuple(chunks))
            with self.subTest(case=case):
                self.assertEqual(streamed, oracle.processed_text)
                self.assertEqual(stream.findings, oracle.findings)


class SecretStreamLifecycleTests(unittest.TestCase):
    def test_default_stream_emits_safe_text_and_redacts_early(self) -> None:
        stream = SecretStream(max_input_chars=128)
        self.assertEqual(stream.feed("safe prefix "), "safe prefix ")
        self.assertEqual(stream.feed("sk-" + "A" * 20), "[REDACTED]")
        self.assertEqual(stream.buffered_chars, 0)
        self.assertEqual(stream.feed(" boundary"), " boundary")
        self.assertEqual(stream.finish(), "")
        self.assertEqual(stream.state, SecretStreamState.FINISHED)
        self.assertEqual(stream.received_chars, 44)
        self.assertEqual(len(stream.findings), 1)

    def test_empty_stream_finishes_cleanly(self) -> None:
        stream = SecretStream()
        self.assertEqual(stream.finish(), "")
        self.assertEqual(stream.findings, ())
        self.assertEqual(stream.state, SecretStreamState.FINISHED)

    def test_partial_prefix_is_held_until_resolved(self) -> None:
        stream = SecretStream(max_input_chars=128)
        self.assertEqual(stream.feed("safe s"), "safe ")
        self.assertEqual(stream.buffered_chars, 1)
        self.assertEqual(stream.feed("k-" + "A" * 20), "[REDACTED]")
        self.assertEqual(stream.finish(), "")

    def test_long_unbounded_candidate_retains_only_chunk_sized_text(self) -> None:
        text = "safe " + "sk-" + "A" * 262_144
        stream = SecretStream(max_input_chars=len(text))
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
        stream = SecretStream(max_input_chars=8)
        stream.feed("sk-")
        with self.assertRaisesRegex(ValueError, "max_input_chars"):
            stream.feed("A" * 6)
        self.assertEqual(stream.state, SecretStreamState.CANCELLED)
        self.assertEqual(stream.buffered_chars, 0)

    def test_internal_failure_cancels_and_releases_source_text(self) -> None:
        class FailingSecretStream(SecretStream):
            def _plan_segment(self, text: str, *, final: bool):
                raise RuntimeError("synthetic planner failure")

        stream = FailingSecretStream(max_input_chars=64)
        with self.assertRaisesRegex(RuntimeError, "synthetic planner"):
            stream.feed("safe input")
        self.assertEqual(stream.state, SecretStreamState.CANCELLED)
        self.assertEqual(stream.buffered_chars, 0)

    def test_cancel_and_finish_are_terminal(self) -> None:
        cancelled = SecretStream()
        cancelled.feed("safe")
        cancelled.cancel()
        cancelled.cancel()
        with self.assertRaisesRegex(RuntimeError, "not open"):
            cancelled.feed("again")
        with self.assertRaisesRegex(RuntimeError, "not open"):
            cancelled.finish()

        finished = SecretStream()
        finished.finish()
        with self.assertRaisesRegex(RuntimeError, "not open"):
            finished.feed("again")

    def test_repr_does_not_disclose_retained_candidate(self) -> None:
        value = "ACME_ABC012AB"
        stream = SecretStream(
            replacement_secret_catalog=_custom_catalog(),
            max_input_chars=64,
        )
        stream.feed(value)
        self.assertNotIn(value, repr(stream))
        self.assertFalse(hasattr(stream, "__dict__"))
        stream.cancel()


class SecretStreamConfigurationTests(unittest.TestCase):
    def test_additional_catalog_extends_builtins(self) -> None:
        stream = SecretStream(
            additional_secret_catalog=_custom_catalog(),
            max_input_chars=128,
        )
        text = "ACME_ABC012AB and sk-" + "A" * 20
        output = stream.feed(text) + stream.finish()
        self.assertEqual(output, "[REDACTED] and [REDACTED]")
        self.assertEqual(len(stream.findings), 2)
        self.assertGreater(
            len(stream.catalog.signatures),
            len(BUILTIN_SECRET_CATALOG.signatures),
        )

    def test_custom_redaction_text_is_used_without_changing_findings(self) -> None:
        stream = SecretStream(max_input_chars=64, redaction_text="<secret>")
        output = stream.feed("sk-" + "A" * 20) + stream.finish()
        self.assertEqual(output, "<secret>")
        self.assertEqual(
            stream.findings[0].redacted_preview,
            "[REDACTED:openai_api_key]",
        )

    def test_rejects_ambiguous_or_unsafe_catalogs(self) -> None:
        catalog = _custom_catalog()
        with self.assertRaisesRegex(ValueError, "mutually exclusive"):
            SecretStream(
                additional_secret_catalog=catalog,
                replacement_secret_catalog=catalog,
            )
        with self.assertRaisesRegex(ValueError, "REDACT"):
            SecretStream(
                replacement_secret_catalog=_custom_catalog(action=Action.BLOCK)
            )
        with self.assertRaisesRegex(ValueError, "unbounded signatures"):
            SecretStream(
                replacement_secret_catalog=_custom_catalog(
                    max_suffix_chars=None,
                    suffix_ending="A",
                )
            )
        with self.assertRaisesRegex(ValueError, "unbounded signatures"):
            SecretStream(
                replacement_secret_catalog=_custom_catalog(
                    max_suffix_chars=None,
                    boundary_chars="ACME_B012X",
                )
            )
        with self.assertRaisesRegex(ValueError, "65536"):
            SecretStream(
                replacement_secret_catalog=_custom_catalog(
                    max_suffix_chars=65_537,
                )
            )

    def test_validates_resource_and_chunk_inputs(self) -> None:
        with self.assertRaises(TypeError):
            SecretStream(max_input_chars=True)
        with self.assertRaises(ValueError):
            SecretStream(max_input_chars=0)
        with self.assertRaises(TypeError):
            SecretStream(redaction_text=object())
        with self.assertRaises(ValueError):
            SecretStream(redaction_text="")
        stream = SecretStream()
        with self.assertRaises(TypeError):
            stream.feed(object())
        with self.assertRaises(ValueError):
            stream.feed("")
        self.assertEqual(stream.state, SecretStreamState.OPEN)


if __name__ == "__main__":
    unittest.main()
