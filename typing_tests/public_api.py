"""Static consumer examples for the supported public API."""

from typing import assert_type

from llm_ffw import (
    AsyncFirewall,
    BidiControlRule,
    ConnectionStringConfig,
    EmailAddressConfig,
    Finding,
    Firewall,
    FirewallConfig,
    FirewallResult,
    FirewallStream,
    IPAddressConfig,
    PhoneNumberConfig,
    RuleEngine,
    SanitizationResult,
    StreamMode,
    ToolCall,
    ToolCallRule,
    ToolDefinition,
    UnsafeURLConfig,
)


config = FirewallConfig(
    connection_string_config=ConnectionStringConfig(),
    email_address_config=EmailAddressConfig(),
    ip_address_config=IPAddressConfig(),
    phone_number_config=PhoneNumberConfig(),
    unsafe_url_config=UnsafeURLConfig(
        denied_hostname_suffixes=("internal.example",),
    ),
)
firewall = Firewall.from_config(config)
assert_type(firewall.sanitize_input("synthetic@example.com"), str)
assert_type(
    firewall.sanitize_input_result("synthetic@example.com"),
    SanitizationResult,
)
assert_type(
    firewall.sanitize_output("synthetic", prompt_context="request"),
    str,
)

engine = RuleEngine()
assert_type(BidiControlRule().rule_id, str)
assert_type(engine.process("synthetic"), FirewallResult)
assert_type(
    engine.stream(mode=StreamMode.AUTO),
    FirewallStream,
)

definition = ToolDefinition(
    "lookup",
    {
        "type": "object",
        "properties": {"query": {"type": "string"}},
        "required": ["query"],
    },
)
call = ToolCall("lookup", {"query": "synthetic"}, "call-1")
assert_type(ToolCallRule((definition,)).validate(call), tuple[Finding, ...])


async def check_async_api() -> None:
    async_firewall = AsyncFirewall.from_config(config)
    assert_type(await async_firewall.sanitize_input("synthetic"), str)
    assert_type(
        await async_firewall.sanitize_input_result("synthetic"),
        SanitizationResult,
    )
