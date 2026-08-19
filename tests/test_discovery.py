from dataclasses import FrozenInstanceError, fields
import unittest

from llm_ffw import (
    BUILTIN_SECRET_CATALOG,
    Firewall,
    FirewallConfig,
    PresetDescriptor,
    PresetRuleDescriptor,
    RuleActivation,
    RuleDescriptor,
    ScanScope,
    available_presets,
    available_rules,
    config_from_preset,
)
from llm_ffw.rules import (
    AuthorizationHeaderRule,
    BannedSubstringsRule,
    BidiControlRule,
    ConnectionStringRule,
    CredentialAssignmentRule,
    EmailAddressRule,
    ExternalResourceRule,
    IBANRule,
    IPAddressRule,
    InvisibleCharactersRule,
    JSONOutputRule,
    JWTTokenRule,
    MACAddressRule,
    PaymentCardRule,
    PhoneNumberRule,
    PrivateKeyRule,
    RepetitionRule,
    SecretsRule,
    ToolCallRule,
    ToolResultRule,
    UnicodeTagSmugglingRule,
    UnsafeURLRule,
)


RULE_TYPES = (
    AuthorizationHeaderRule,
    BannedSubstringsRule,
    BidiControlRule,
    ConnectionStringRule,
    CredentialAssignmentRule,
    EmailAddressRule,
    ExternalResourceRule,
    IBANRule,
    IPAddressRule,
    InvisibleCharactersRule,
    JSONOutputRule,
    JWTTokenRule,
    MACAddressRule,
    PaymentCardRule,
    PhoneNumberRule,
    PrivateKeyRule,
    RepetitionRule,
    SecretsRule,
    ToolCallRule,
    ToolResultRule,
    UnicodeTagSmugglingRule,
    UnsafeURLRule,
)


class DiscoveryTests(unittest.TestCase):
    def test_every_builtin_rule_is_discoverable_in_stable_id_order(self) -> None:
        descriptors = available_rules()
        actual = {descriptor.rule_id: descriptor for descriptor in descriptors}

        self.assertEqual(len(descriptors), 22)
        self.assertEqual(
            tuple(descriptor.rule_id for descriptor in descriptors),
            tuple(sorted(actual)),
        )
        self.assertEqual(set(actual), {rule_type.RULE_ID for rule_type in RULE_TYPES})
        for rule_type in RULE_TYPES:
            with self.subTest(rule_id=rule_type.RULE_ID):
                descriptor = actual[rule_type.RULE_ID]
                self.assertEqual(descriptor.purpose, rule_type.PURPOSE)
                declared_scopes = getattr(
                    rule_type,
                    "SCOPES",
                    frozenset((ScanScope.INPUT, ScanScope.OUTPUT)),
                )
                self.assertEqual(
                    descriptor.supported_scopes,
                    tuple(sorted(declared_scopes, key=lambda scope: scope.value)),
                )

    def test_activation_and_deployment_value_contracts_are_exact(self) -> None:
        descriptors = {item.rule_id: item for item in available_rules()}
        defaults = {
            item.rule_id
            for item in descriptors.values()
            if item.activation is RuleActivation.DEFAULT
        }
        explicit = {
            item.rule_id
            for item in descriptors.values()
            if item.activation is RuleActivation.EXPLICIT
        }
        deployment_values = {
            item.rule_id
            for item in descriptors.values()
            if item.requires_deployment_value
        }

        self.assertEqual(
            defaults,
            {
                "pii.payment_card",
                "secrets.detected",
                "secrets.jwt_token",
                "secrets.private_key",
                "unicode.bidi_controls",
                "unicode.invisible_characters",
                "unicode.tag_smuggling",
            },
        )
        self.assertEqual(
            explicit,
            {"tools.call.validity", "tools.result.validity"},
        )
        self.assertEqual(
            deployment_values,
            {"content.banned_substrings", "tools.call.validity"},
        )
        self.assertEqual(
            sum(
                item.activation is RuleActivation.OPT_IN
                for item in descriptors.values()
            ),
            13,
        )

    def test_named_presets_match_constructed_firewall_capabilities(self) -> None:
        expected_configs = {
            "all-text": FirewallConfig.all_text_rules(),
            "default": FirewallConfig.default(),
            "json-api": FirewallConfig.json_api(),
            "privacy-input": FirewallConfig.privacy_input(),
        }
        descriptors = available_presets()

        self.assertEqual(
            tuple(item.preset_id for item in descriptors),
            tuple(sorted(expected_configs)),
        )
        for descriptor in descriptors:
            with self.subTest(preset_id=descriptor.preset_id):
                config = config_from_preset(descriptor.preset_id)
                self.assertEqual(config, expected_configs[descriptor.preset_id])
                firewall = Firewall.from_config(config)
                try:
                    actual = {
                        item.rule_id: item.scopes
                        for item in firewall.capabilities().rules
                    }
                finally:
                    firewall.close()
                self.assertEqual(
                    actual,
                    {item.rule_id: item.scopes for item in descriptor.rules},
                )

    def test_all_text_preset_guarantees_only_self_contained_rules(self) -> None:
        preset = next(
            item for item in available_presets() if item.preset_id == "all-text"
        )
        rule_ids = {item.rule_id for item in preset.rules}

        self.assertEqual(len(rule_ids), 19)
        self.assertNotIn("content.banned_substrings", rule_ids)
        banned = next(
            item
            for item in available_rules()
            if item.rule_id == "content.banned_substrings"
        )
        self.assertIs(banned.activation, RuleActivation.OPT_IN)
        self.assertTrue(banned.requires_deployment_value)

    def test_preset_resolution_rejects_unknown_and_non_string_ids(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown preset_id"):
            config_from_preset("DEFAULT")
        with self.assertRaisesRegex(TypeError, "preset_id must be a string"):
            config_from_preset(1)  # type: ignore[arg-type]

    def test_descriptors_are_validated_immutable_and_disclosure_safe(self) -> None:
        descriptor = available_rules()[0]
        with self.assertRaises(FrozenInstanceError):
            descriptor.purpose = "changed"  # type: ignore[misc]
        with self.assertRaises(ValueError):
            RuleDescriptor(
                "",
                "purpose",
                (ScanScope.INPUT,),
                RuleActivation.DEFAULT,
            )
        with self.assertRaises(TypeError):
            RuleDescriptor(
                "rule",
                "purpose",
                (ScanScope.INPUT,),
                "default",  # type: ignore[arg-type]
            )
        with self.assertRaises(ValueError):
            PresetDescriptor(
                "duplicate",
                "purpose",
                (
                    PresetRuleDescriptor("rule", (ScanScope.INPUT,)),
                    PresetRuleDescriptor("rule", (ScanScope.OUTPUT,)),
                ),
            )

        self.assertEqual(
            {field.name for field in fields(RuleDescriptor)},
            {
                "activation",
                "purpose",
                "requires_deployment_value",
                "rule_id",
                "supported_scopes",
            },
        )
        rendered = repr((available_rules(), available_presets()))
        for signature in BUILTIN_SECRET_CATALOG.signatures:
            for prefix in signature.prefixes:
                self.assertNotIn(prefix, rendered)


if __name__ == "__main__":
    unittest.main()
