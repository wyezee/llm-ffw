"""Run deterministic consumer acceptance scenarios against the public facade."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import math
from time import perf_counter

from llm_ffw import Firewall, ProcessScannerPoolConfig


@dataclass(frozen=True, slots=True)
class AcceptanceScenario:
    """One synthetic caller-visible input/output expectation."""

    scenario_id: str
    scope: str
    text: str
    expected_text: str
    protected: bool

    def __post_init__(self) -> None:
        if not self.scenario_id:
            raise ValueError("scenario_id must not be empty")
        if self.scope not in ("input", "output"):
            raise ValueError("scope must be input or output")


@dataclass(frozen=True, slots=True)
class AcceptanceResult:
    """Aggregate acceptance evidence that never retains scenario text."""

    scenario_count: int
    safe_scenario_count: int
    protected_scenario_count: int
    sequential_requests: int
    concurrent_requests: int
    p95_latency_ms: float
    p99_latency_ms: float
    final_state: str


def _tagged(value: str) -> str:
    return "".join(chr(0xE0000 + ord(character)) for character in value)


def _default_scenarios() -> tuple[AcceptanceScenario, ...]:
    private_key = (
        "-----BEGIN PRIVATE KEY-----\n"
        "QUJDREVGR0hJSktMTU5PUA==\n"
        "-----END PRIVATE KEY-----"
    )
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJzeW50aGV0aWMtdXNlciJ9."
        "c2lnbmF0dXJl"
    )
    return (
        AcceptanceScenario(
            "safe-python-environment-reference",
            "input",
            'api_key = os.environ["OPENAI_API_KEY"]',
            'api_key = os.environ["OPENAI_API_KEY"]',
            False,
        ),
        AcceptanceScenario(
            "safe-placeholder-secret",
            "input",
            "Set OPENAI_API_KEY=sk-REPLACE_ME in the deployment environment.",
            "Set OPENAI_API_KEY=sk-REPLACE_ME in the deployment environment.",
            False,
        ),
        AcceptanceScenario(
            "safe-json-field-names",
            "output",
            '{"api_key_env":"PAYMENTS_API_KEY","auth_scheme":"bearer token"}',
            '{"api_key_env":"PAYMENTS_API_KEY","auth_scheme":"bearer token"}',
            False,
        ),
        AcceptanceScenario(
            "safe-source-code-url",
            "input",
            'fetch("https://api.example.com/v1/orders/{order_id}")',
            'fetch("https://api.example.com/v1/orders/{order_id}")',
            False,
        ),
        AcceptanceScenario(
            "safe-enterprise-identifiers",
            "input",
            "tenant=550e8400-e29b-41d4-a716-446655440000 commit=0123456789abcdef",
            "tenant=550e8400-e29b-41d4-a716-446655440000 commit=0123456789abcdef",
            False,
        ),
        AcceptanceScenario(
            "safe-invalid-card-lookalike",
            "output",
            "Order reference 4242424242424241 is not a payment credential.",
            "Order reference 4242424242424241 is not a payment credential.",
            False,
        ),
        AcceptanceScenario(
            "safe-jwt-lookalike",
            "input",
            "The documented compact form is header.payload.signature.",
            "The documented compact form is header.payload.signature.",
            False,
        ),
        AcceptanceScenario(
            "safe-pem-documentation-reference",
            "input",
            "Documentation refers to BEGIN PRIVATE KEY armor without embedding it.",
            "Documentation refers to BEGIN PRIVATE KEY armor without embedding it.",
            False,
        ),
        AcceptanceScenario(
            "safe-multilingual-code-review",
            "output",
            "Review passed: नमस्ते, こんにちは, مرحبا, and emoji ✅.",
            "Review passed: नमस्ते, こんにちは, مرحبا, and emoji ✅.",
            False,
        ),
        AcceptanceScenario(
            "protect-provider-secret",
            "input",
            "Authorization value: sk-" + "A" * 20,
            "Authorization value: [REDACTED]",
            True,
        ),
        AcceptanceScenario(
            "protect-invisible-character",
            "input",
            "approve\u200bpayment",
            "approvepayment",
            True,
        ),
        AcceptanceScenario(
            "protect-unicode-tag-smuggling",
            "input",
            "visible" + _tagged("hidden"),
            "visible",
            True,
        ),
        AcceptanceScenario(
            "protect-payment-card",
            "output",
            "Card 4242424242424242",
            "Card [REDACTED]",
            True,
        ),
        AcceptanceScenario(
            "protect-private-key",
            "output",
            private_key,
            "[REDACTED]",
            True,
        ),
        AcceptanceScenario(
            "protect-jwt",
            "input",
            jwt,
            "[REDACTED]",
            True,
        ),
    )


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        raise ValueError("percentile requires at least one value")
    ordered = sorted(values)
    rank = max(1, math.ceil(len(ordered) * percentile / 100))
    return ordered[rank - 1]


def _sanitize(firewall: Firewall, scenario: AcceptanceScenario) -> str:
    if scenario.scope == "input":
        result = firewall.sanitize_input_result(scenario.text)
    else:
        result = firewall.sanitize_output_result(
            scenario.text,
            prompt_context="Synthetic RC consumer acceptance scenario.",
        )
    return result.text


def _execute(
    firewall: Firewall,
    scenario: AcceptanceScenario,
) -> float:
    started = perf_counter()
    actual = _sanitize(firewall, scenario)
    elapsed_ms = (perf_counter() - started) * 1_000
    if actual != scenario.expected_text:
        raise AssertionError(
            f"acceptance scenario failed: {scenario.scenario_id}"
        )
    return elapsed_ms


def run_acceptance(
    *,
    workers: int = 2,
    concurrency: int = 4,
    rounds: int = 2,
    max_tasks_per_child: int = 4,
    max_p99_latency_ms: float = 5_000,
) -> AcceptanceResult:
    """Exercise defaults through the public process-backed consumer facade."""

    for value, name in (
        (workers, "workers"),
        (concurrency, "concurrency"),
        (rounds, "rounds"),
        (max_tasks_per_child, "max_tasks_per_child"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if concurrency < workers:
        raise ValueError("concurrency must be at least workers")
    if (
        isinstance(max_p99_latency_ms, bool)
        or not isinstance(max_p99_latency_ms, (int, float))
        or not math.isfinite(max_p99_latency_ms)
        or max_p99_latency_ms <= 0
    ):
        raise ValueError("max_p99_latency_ms must be finite and positive")

    scenarios = _default_scenarios()
    latencies: list[float] = []
    concurrent_requests = 0
    firewall = Firewall(
        pool_config=ProcessScannerPoolConfig(
            max_workers=workers,
            max_in_flight=concurrency,
            max_tasks_per_child=max_tasks_per_child,
            admission_timeout_seconds=5.0,
        ),
        request_timeout_seconds=10.0,
    )
    with firewall:
        for scenario in scenarios:
            latencies.append(_execute(firewall, scenario))

        work = scenarios * rounds
        with ThreadPoolExecutor(max_workers=concurrency) as callers:
            futures = [
                callers.submit(_execute, firewall, scenario)
                for scenario in work
            ]
            for future in futures:
                latencies.append(future.result())
                concurrent_requests += 1

    p95 = _percentile(latencies, 95)
    p99 = _percentile(latencies, 99)
    if p99 > max_p99_latency_ms:
        raise AssertionError(
            "acceptance p99 latency exceeded threshold: "
            f"{p99:.3f} ms > {max_p99_latency_ms:.3f} ms"
        )
    return AcceptanceResult(
        scenario_count=len(scenarios),
        safe_scenario_count=sum(not item.protected for item in scenarios),
        protected_scenario_count=sum(item.protected for item in scenarios),
        sequential_requests=len(scenarios),
        concurrent_requests=concurrent_requests,
        p95_latency_ms=p95,
        p99_latency_ms=p99,
        final_state=firewall.state.value,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--max-tasks-per-child", type=int, default=4)
    parser.add_argument("--max-p99-latency-ms", type=float, default=5_000)
    return parser


def main() -> None:
    args = _parser().parse_args()
    result = run_acceptance(
        workers=args.workers,
        concurrency=args.concurrency,
        rounds=args.rounds,
        max_tasks_per_child=args.max_tasks_per_child,
        max_p99_latency_ms=args.max_p99_latency_ms,
    )
    print(f"scenarios={result.scenario_count}")
    print(f"safe_scenarios={result.safe_scenario_count}")
    print(f"protected_scenarios={result.protected_scenario_count}")
    print(f"sequential_requests={result.sequential_requests}")
    print(f"concurrent_requests={result.concurrent_requests}")
    print(f"p95_latency_ms={result.p95_latency_ms:.3f}")
    print(f"p99_latency_ms={result.p99_latency_ms:.3f}")
    print(f"final_state={result.final_state}")
    print("rc_acceptance=passed")


if __name__ == "__main__":
    main()
