import pickle
import unittest

from llm_ffw import (
    AuthorizationHeaderConfig,
    BannedSubstring,
    BannedSubstringCatalog,
    ConnectionStringConfig,
    EmailAddressConfig,
    ExternalResourceConfig,
    IBANConfig,
    IPAddressConfig,
    JSONOutputConfig,
    JWTTokenConfig,
    MACAddressConfig,
    PaymentCardConfig,
    PhoneNumberConfig,
    PrivateKeyConfig,
    RepetitionConfig,
    ScanScope,
    UnsafeURLConfig,
)
from llm_ffw._rule_registry import (
    REGISTERED_RULE_IDS,
    RULE_SPECS,
    build_registered_rules,
    normalize_rule_configs,
    registered_rule_capabilities,
    registered_rule_ids,
)


def _all_config_pairs() -> tuple[tuple[str, object], ...]:
    return (
        (
            "banned_substring_catalog",
            BannedSubstringCatalog(
                "test.registry",
                "1",
                (BannedSubstring("test.marker", "registry-marker"),),
            ),
        ),
        ("json_output_config", JSONOutputConfig()),
        ("unsafe_url_config", UnsafeURLConfig()),
        ("external_resource_config", ExternalResourceConfig()),
        ("ip_address_config", IPAddressConfig()),
        ("mac_address_config", MACAddressConfig()),
        ("iban_config", IBANConfig()),
        ("authorization_header_config", AuthorizationHeaderConfig()),
        ("connection_string_config", ConnectionStringConfig()),
        ("email_address_config", EmailAddressConfig()),
        ("phone_number_config", PhoneNumberConfig()),
        ("payment_card_config", PaymentCardConfig()),
        ("private_key_config", PrivateKeyConfig()),
        ("jwt_token_config", JWTTokenConfig()),
        ("repetition_config", RepetitionConfig()),
    )


class RuleRegistryTests(unittest.TestCase):
    def test_registry_is_fixed_unique_and_builds_every_registered_rule(self) -> None:
        configured = normalize_rule_configs(reversed(_all_config_pairs()))
        rules = build_registered_rules(configured)
        capabilities = registered_rule_capabilities(configured)

        self.assertEqual(len(RULE_SPECS), 15)
        self.assertEqual(
            tuple(field_name for field_name, _ in configured),
            tuple(spec.config_field for spec in RULE_SPECS),
        )
        self.assertEqual(
            tuple(rule.rule_id for rule in rules),
            tuple(spec.rule_id for spec in RULE_SPECS),
        )
        self.assertEqual(
            tuple(item.rule_id for item in capabilities),
            tuple(spec.rule_id for spec in RULE_SPECS),
        )
        self.assertEqual(registered_rule_ids(configured), REGISTERED_RULE_IDS)
        self.assertEqual(
            next(
                item.scopes
                for item in capabilities
                if item.rule_id == "output.json.validity"
            ),
            (ScanScope.OUTPUT,),
        )
        self.assertEqual(
            next(
                item.scopes
                for item in capabilities
                if item.rule_id == "output.external_resource"
            ),
            (ScanScope.OUTPUT,),
        )
        self.assertEqual(
            next(
                item.scopes
                for item in capabilities
                if item.rule_id == "pii.phone_number"
            ),
            (ScanScope.INPUT,),
        )

    def test_normalized_configs_are_spawn_pickle_safe(self) -> None:
        configured = normalize_rule_configs(_all_config_pairs())

        restored = pickle.loads(pickle.dumps(configured))

        self.assertEqual(restored, configured)
        self.assertEqual(registered_rule_ids(restored), REGISTERED_RULE_IDS)

    def test_registry_rejects_unknown_duplicate_and_wrong_config_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown configured rule field"):
            normalize_rule_configs((("untrusted_plugin", PhoneNumberConfig()),))
        with self.assertRaisesRegex(ValueError, "duplicate configured rule field"):
            normalize_rule_configs(
                (
                    ("phone_number_config", None),
                    ("phone_number_config", PhoneNumberConfig()),
                )
            )
        with self.assertRaisesRegex(TypeError, "must be a PhoneNumberConfig"):
            normalize_rule_configs(
                (("phone_number_config", EmailAddressConfig()),)
            )


if __name__ == "__main__":
    unittest.main()
