"""Deterministic labeled accuracy corpus for opt-in PII rules."""

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import random

from llm_ffw import (
    EmailAddressConfig,
    EmailAddressRule,
    IPAddressConfig,
    IPAddressRule,
    MACAddressConfig,
    MACAddressRule,
    IBANConfig,
    IBANRule,
    ScanScope,
    RuleScanner,
)
from llm_ffw.iban import IBAN_LENGTHS


_MANIFEST_PATH = Path(__file__).with_name("pii_accuracy_manifest.json")
_RULE_IDS = (
    EmailAddressRule.RULE_ID,
    IPAddressRule.RULE_ID,
    MACAddressRule.RULE_ID,
    IBANRule.RULE_ID,
)


@dataclass(frozen=True, slots=True)
class ExpectedPIIFinding:
    """Expected rule ownership and exact character span."""

    rule_id: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class PIIAccuracyScenario:
    """One synthetic labeled input without any real personal data."""

    scenario_id: str
    category: str
    text: str
    expected: tuple[ExpectedPIIFinding, ...]


@dataclass(frozen=True, slots=True)
class PIIAccuracyCorpus:
    """Reproducible in-memory scenarios and safe provenance metadata."""

    dataset_id: str
    seed: int
    uses_llm: bool
    uses_network: bool
    synthetic_examples_only: bool
    scenarios: tuple[PIIAccuracyScenario, ...]

    @property
    def sha256(self) -> str:
        """Hash canonical scenario data for reproducibility."""

        serialized = json.dumps(
            [
                {
                    "scenario_id": scenario.scenario_id,
                    "category": scenario.category,
                    "text": scenario.text,
                    "expected": [
                        {
                            "rule_id": finding.rule_id,
                            "start": finding.start,
                            "end": finding.end,
                        }
                        for finding in scenario.expected
                    ],
                }
                for scenario in self.scenarios
            ],
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class RuleAccuracy:
    """Disclosure-safe confusion counts for one rule."""

    rule_id: str
    expected_findings: int
    true_positives: int
    false_positives: int
    false_negatives: int


@dataclass(frozen=True, slots=True)
class CategoryAccuracy:
    """Disclosure-safe confusion counts for one scenario category."""

    category: str
    scenario_count: int
    expected_findings: int
    actual_findings: int
    true_positives: int
    true_negative_scenarios: int
    false_positives: int
    false_negatives: int
    redaction_failures: int


@dataclass(frozen=True, slots=True)
class PIIAccuracyReport:
    """Aggregate evidence without retaining scenario text."""

    dataset_id: str
    corpus_sha256: str
    scenario_count: int
    expected_findings: int
    actual_findings: int
    true_positives: int
    true_negative_scenarios: int
    false_positives: int
    false_negatives: int
    redaction_failures: int
    rules: tuple[RuleAccuracy, ...]
    categories: tuple[CategoryAccuracy, ...]

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 1.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 1.0

    @property
    def exact_span_rate(self) -> float:
        return (
            self.true_positives / self.expected_findings
            if self.expected_findings
            else 1.0
        )


def _load_manifest(path: Path) -> dict[str, object]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("PII accuracy manifest must be an object")
    expected_keys = {
        "schema_version",
        "dataset_id",
        "seed",
        "uses_llm",
        "uses_network",
        "synthetic_examples_only",
        "groups",
        "expected_sha256",
    }
    if set(manifest) != expected_keys:
        raise ValueError("PII accuracy manifest fields are invalid")
    if manifest["schema_version"] != 4:
        raise ValueError("unsupported PII accuracy manifest schema")
    if not isinstance(manifest["dataset_id"], str):
        raise TypeError("dataset_id must be a string")
    if isinstance(manifest["seed"], bool) or not isinstance(
        manifest["seed"], int
    ):
        raise TypeError("seed must be an integer")
    for field_name in (
        "uses_llm",
        "uses_network",
        "synthetic_examples_only",
    ):
        if not isinstance(manifest[field_name], bool):
            raise TypeError(f"{field_name} must be a boolean")
    groups = manifest["groups"]
    expected_groups = {
        "email_positive",
        "ip_positive",
        "mac_positive",
        "iban_positive",
        "mixed_positive",
        "negative",
        "curated_email_positive",
        "curated_ip_positive",
        "curated_mac_positive",
        "curated_mac_negative",
        "curated_iban_negative",
        "curated_negative",
    }
    if not isinstance(groups, dict) or set(groups) != expected_groups:
        raise ValueError("PII accuracy groups are invalid")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in groups.values()
    ):
        raise ValueError("PII accuracy group counts must be positive integers")
    if not isinstance(manifest["expected_sha256"], str):
        raise TypeError("expected_sha256 must be a string")
    return manifest


def _finding(rule_id: str, text: str, value: str) -> ExpectedPIIFinding:
    start = text.index(value)
    return ExpectedPIIFinding(rule_id, start, start + len(value))


def _email_scenarios(count: int) -> list[PIIAccuracyScenario]:
    domains = (
        "example.com",
        "sub.example.org",
        "service.example.net",
        "mail.example.test",
        "mail.example.invalid",
    )
    contexts = (
        "Contact <{value}>.",
        "owner={value}",
        'record={{"email":"{value}"}}',
        "https://example.test/?owner={value}&source=synthetic",
    )
    scenarios: list[PIIAccuracyScenario] = []
    for index in range(count):
        local_parts = (
            f"user{index}",
            f"first.last{index}",
            f"team+tag{index}",
            f"account_{index}",
            f"percent%{index}",
        )
        local_part = local_parts[index % len(local_parts)]
        domain = domains[index % len(domains)]
        value = f"{local_part}@{domain}"
        text = contexts[index % len(contexts)].format(value=value)
        scenarios.append(
            PIIAccuracyScenario(
                scenario_id=f"email-positive-{index:04d}",
                category="email_positive",
                text=text,
                expected=(_finding(EmailAddressRule.RULE_ID, text, value),),
            )
        )
    return scenarios


def _ip_value(index: int) -> str:
    if index % 2 == 0:
        networks = ("192.0.2", "198.51.100", "203.0.113")
        return f"{networks[index % len(networks)]}.{index % 254 + 1}"
    return f"2001:db8:{index:x}::{index % 65_535 + 1:x}"


def _ip_scenarios(count: int) -> list[PIIAccuracyScenario]:
    contexts = (
        "source={value}",
        "endpoint=[{value}]",
        'record={{"address":"{value}"}}',
        "route from {value} to the synthetic service",
    )
    scenarios: list[PIIAccuracyScenario] = []
    for index in range(count):
        value = _ip_value(index)
        text = contexts[index % len(contexts)].format(value=value)
        scenarios.append(
            PIIAccuracyScenario(
                scenario_id=f"ip-positive-{index:04d}",
                category="ip_positive",
                text=text,
                expected=(_finding(IPAddressRule.RULE_ID, text, value),),
            )
        )
    return scenarios


def _mac_value(index: int) -> str:
    """Return a deterministic, locally administered synthetic EUI-48 value."""

    octets = (2, 0, (index >> 16) & 255, (index >> 8) & 255, index & 255, 1)
    separator = ":" if index % 2 == 0 else "-"
    return separator.join(f"{octet:02X}" for octet in octets)


def _mac_scenarios(count: int) -> list[PIIAccuracyScenario]:
    contexts = (
        "adapter={value}",
        "device [{value}]",
        'record={{"mac":"{value}"}}',
        "synthetic interface {value} is active",
    )
    scenarios: list[PIIAccuracyScenario] = []
    for index in range(count):
        value = _mac_value(index)
        text = contexts[index % len(contexts)].format(value=value)
        scenarios.append(
            PIIAccuracyScenario(
                scenario_id=f"mac-positive-{index:04d}",
                category="mac_positive",
                text=text,
                expected=(_finding(MACAddressRule.RULE_ID, text, value),),
            )
        )
    return scenarios


def _iban_mod97(country: str, bban: str) -> str:
    remainder = 0
    for character in bban + country + "00":
        if "0" <= character <= "9":
            remainder = (remainder * 10 + ord(character) - ord("0")) % 97
        else:
            remainder = (
                remainder * 100 + ord(character) - ord("A") + 10
            ) % 97
    return f"{98 - remainder:02d}"


def _iban_scenarios(count: int) -> list[PIIAccuracyScenario]:
    """Return one synthetic checksum-valid value per registered country."""

    if count != len(IBAN_LENGTHS):
        raise ValueError("IBAN positive count must match the pinned registry")
    contexts = (
        "account={value}",
        "beneficiary [{value}]",
        'record={{"iban":"{value}"}}',
        "synthetic transfer destination {value}.",
    )
    scenarios: list[PIIAccuracyScenario] = []
    for index, (country, length) in enumerate(IBAN_LENGTHS.items()):
        bban = f"{index + 1:0{length - 4}d}"
        value = country + _iban_mod97(country, bban) + bban
        text = contexts[index % len(contexts)].format(value=value)
        scenarios.append(
            PIIAccuracyScenario(
                scenario_id=f"iban-positive-{country.lower()}",
                category="iban_positive",
                text=text,
                expected=(_finding(IBANRule.RULE_ID, text, value),),
            )
        )
    return scenarios


def _mixed_scenarios(count: int) -> list[PIIAccuracyScenario]:
    scenarios: list[PIIAccuracyScenario] = []
    for index in range(count):
        email = f"mixed.user+{index}@example.com"
        address = _ip_value(index + 1_000)
        text = f"contact {email} from {address}"
        scenarios.append(
            PIIAccuracyScenario(
                scenario_id=f"mixed-positive-{index:04d}",
                category="mixed_positive",
                text=text,
                expected=(
                    _finding(EmailAddressRule.RULE_ID, text, email),
                    _finding(IPAddressRule.RULE_ID, text, address),
                ),
            )
        )
    return scenarios


def _negative_scenarios(count: int) -> list[PIIAccuracyScenario]:
    templates = (
        "release {a}.{b}.{c}.{d}-beta",
        "invalid address 999.{b}.{c}.{d}",
        "semantic version {a}.{b}.{c}",
        "clock value 12:34:56",
        "mailbox user{n}@example",
        "mailbox .user{n}@example.com",
        "mailbox user..{n}@example.com",
        "mailbox user{n}@example.1",
        "mailbox user{n}@exam_ple.com",
        "placeholder user{n}_at_example_dot_com",
        "invalid route 10.20.30.999",
        "short IPv6 form 2001:db8:{a}",
        "mailbox user{n}@-example.com",
        "mailbox user{n}@example.c",
        "commit 0123456789abcdef and tenant 550e8400-e29b-41d4-a716-446655440000",
        "documentation mentions email and IP address fields without values",
    )
    scenarios: list[PIIAccuracyScenario] = []
    for index in range(count):
        text = templates[index % len(templates)].format(
            n=index,
            a=index % 9 + 1,
            b=index % 17 + 1,
            c=index % 29 + 1,
            d=index % 251 + 1,
        )
        scenarios.append(
            PIIAccuracyScenario(
                scenario_id=f"negative-{index:04d}",
                category="negative",
                text=text,
                expected=(),
            )
        )
    return scenarios


def _curated_positive_scenario(
    scenario_id: str,
    category: str,
    rule_id: str,
    value: str,
    template: str,
) -> PIIAccuracyScenario:
    text = template.format(value=value)
    return PIIAccuracyScenario(
        scenario_id=scenario_id,
        category=category,
        text=text,
        expected=(_finding(rule_id, text, value),),
    )


def _curated_email_scenarios(count: int) -> list[PIIAccuracyScenario]:
    """Return explicit syntax boundaries in reserved DNS namespaces."""

    cases = (
        ("user@example.com", "Contact ({value}), please."),
        ("USER@EXAMPLE.COM", "Uppercase <{value}>."),
        ("first.last@example.org", "owner={value};status=active"),
        ("team+alerts@example.net", "mailto:{value}?subject=synthetic"),
        ("account_name@example.test", 'record={{"email":"{value}"}}'),
        ("percent%tag@example.invalid", "recipient [{value}]"),
        ("a@example.com", "minimal local part: {value}"),
        ("customer@sub.example.org", "nested domain {value}."),
        ("user@xn--bcher-kva.example", "punycode {value}"),
        ("ops@deep.sub.example.com", "path/{value}?source=test"),
        ("tag+one@service.example.net", "before\t{value}\tafter"),
        ("under_score@example.com", "CSV,{value},synthetic"),
        ("dash-tag@example.com", "Markdown **{value}**"),
        ("plus+two@example.org", "query owner={value}&ok=1"),
        ("mixed.Case+tag@example.test", "value='{value}'"),
        ("x%y@example.invalid", "percent local {value}"),
        ("a" * 64 + "@example.com", "max local <{value}>"),
        ("a@" + "b" * 63 + ".example", "max label <{value}>"),
        ("edge@example.com", "sentence starts {value}."),
        ("final@example.org", "{value}"),
    )
    if len(cases) != count:
        raise ValueError("curated email count does not match manifest")
    return [
        _curated_positive_scenario(
            f"curated-email-positive-{index:04d}",
            "curated_email_positive",
            EmailAddressRule.RULE_ID,
            value,
            template,
        )
        for index, (value, template) in enumerate(cases)
    ]


def _curated_ip_scenarios(count: int) -> list[PIIAccuracyScenario]:
    """Return explicit canonical forms in non-user-assigned address space."""

    cases = (
        ("192.0.2.0", "network edge ({value})"),
        ("192.0.2.255", "broadcast-shaped {value}."),
        ("198.51.100.1", "host={value}:443"),
        ("203.0.113.254", "CIDR {value}/24"),
        ("192.0.2.42", 'record={{"ip":"{value}"}}'),
        ("198.51.100.200", "route from {value}, then continue"),
        ("0.0.0.0", "unspecified {value}"),
        ("127.0.0.1", "loopback {value}:8080"),
        ("10.0.0.1", "private endpoint {value}"),
        ("172.16.0.1", "private endpoint [{value}]"),
        ("192.168.255.255", "private boundary {value}"),
        ("169.254.1.1", "link-local {value}"),
        ("255.255.255.255", "limited broadcast {value}"),
        ("2001:db8::", "IPv6 [{value}]"),
        ("2001:db8::1", "endpoint=[{value}]:443"),
        ("2001:db8:0:1:1:1:1:1", "expanded {value}."),
        ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "boundary {value}"),
        ("2001:db8::192.0.2.128", "mapped syntax [{value}]"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "full {value}"),
        ("::", "unspecified IPv6 [{value}]"),
        ("::1", "loopback IPv6 [{value}]"),
        ("fe80::1", "link-local IPv6 [{value}]"),
        ("2001:db8:abcd::1234", "CSV,{value},synthetic"),
        ("203.0.113.7", "{value}"),
    )
    if len(cases) != count:
        raise ValueError("curated IP count does not match manifest")
    return [
        _curated_positive_scenario(
            f"curated-ip-positive-{index:04d}",
            "curated_ip_positive",
            IPAddressRule.RULE_ID,
            value,
            template,
        )
        for index, (value, template) in enumerate(cases)
    ]


def _curated_mac_scenarios(count: int) -> list[PIIAccuracyScenario]:
    """Return explicit EUI-48 boundaries using local synthetic identifiers."""

    values = (
        "02:00:00:00:00:00",
        "02:00:00:00:00:01",
        "02:FF:FF:FF:FF:FF",
        "06:12:34:56:78:9A",
        "0A:BC:DE:F0:12:34",
        "0E:01:23:45:67:89",
        "02:aa:bb:cc:dd:ee",
        "06:aB:cD:eF:01:23",
        "02-00-00-00-00-00",
        "02-00-00-00-00-01",
        "02-FF-FF-FF-FF-FF",
        "06-12-34-56-78-9A",
        "0A-BC-DE-F0-12-34",
        "0E-01-23-45-67-89",
        "02-aa-bb-cc-dd-ee",
        "06-aB-cD-eF-01-23",
        "02:10:20:30:40:50",
        "06:60:70:80:90:A0",
        "0A-B0-C0-D0-E0-F0",
        "0E-11-22-33-44-55",
    )
    templates = (
        "adapter ({value})",
        "device={value};active=true",
        'record={{"address":"{value}"}}',
        "before\t{value}\tafter",
    )
    if len(values) != count:
        raise ValueError("curated MAC count does not match manifest")
    return [
        _curated_positive_scenario(
            f"curated-mac-positive-{index:04d}",
            "curated_mac_positive",
            MACAddressRule.RULE_ID,
            value,
            templates[index % len(templates)],
        )
        for index, value in enumerate(values)
    ]


def _curated_mac_negative_scenarios(count: int) -> list[PIIAccuracyScenario]:
    """Return MAC lookalikes outside the supported canonical syntax."""

    texts = (
        "mixed 02:00-00:00:00:01",
        "Cisco 0200.0000.0001",
        "short 02:00:00:00:00",
        "long 02:00:00:00:00:01:02",
        "EUI-64 02-00-00-00-00-00-00-01",
        "bad hex 02:00:00:00:00:GG",
        "single digits 2:0:0:0:0:1",
        "triple digits 002:00:00:00:00:01",
        "embedded host02:00:00:00:00:01",
        "embedded 02:00:00:00:00:01host",
        "underscore x_02:00:00:00:00:01",
        "suffix 02:00:00:00:00:01_x",
        "prefix-dot x.02:00:00:00:00:01",
        "suffix-dot 02:00:00:00:00:01.example",
        "spaces 02 : 00 : 00 : 00 : 00 : 01",
        "commas 02,00,00,00,00,01",
        "compact 020000000001",
        "invalid IPv6 2001:db8:::1",
        "UUID 550e8400-e29b-41d4-a716-446655440000",
        "clock 12:34:56",
        "date 20-26-08-17",
        "version AA-BB-CC",
        "empty colons : :",
        "hyphen chain 02-00-00-00-00-01-extra",
        "colon chain 02:00:00:00:00:01:extra",
        "fullwidth ０２:００:００:００:００:０１",
        "Arabic digits ٠٢:٠٠:٠٠:٠٠:٠٠:٠١",
        "zero width 02:\u200b00:00:00:00:01",
        "label <mac-address>",
        "template {{mac_address}}",
        "documentation says MAC address without a value",
        "ordinary prose with no hardware identifier",
    )
    if len(texts) != count:
        raise ValueError("curated MAC negative count does not match manifest")
    return [
        PIIAccuracyScenario(
            scenario_id=f"curated-mac-negative-{index:04d}",
            category="curated_mac_negative",
            text=text,
            expected=(),
        )
        for index, text in enumerate(texts)
    ]


def _curated_iban_negative_scenarios(
    count: int,
) -> list[PIIAccuracyScenario]:
    """Return invalid checksums, lengths, alphabets, and boundaries."""

    texts = (
        "bad checksum DE00370400440532013000",
        "bad checksum GB00NWBK60161331926819",
        "short DE8937040044053201300",
        "long DE893704004405320130000",
        "unknown US89370400440532013000",
        "lowercase de89370400440532013000",
        "mixed case De89370400440532013000",
        "hyphens DE89-3704-0044-0532-0130-00",
        "double spaces DE89  3704 0044 0532 0130 00",
        "tabs DE89\t3704\t0044\t0532\t0130\t00",
        "embedded prefixDE89370400440532013000",
        "embedded DE89370400440532013000suffix",
        "underscore DE89370400440532013000_suffix",
        "punctuation DE89.3704.0044.0532.0130.00",
        "slashes DE89/3704/0044/0532/0130/00",
        "fullwidth ＤＥ８９３７０４００４４０５３２０１３０００",
        "zero width DE89\u200b370400440532013000",
        "letter check digits DEA9370400440532013000",
        "digit country 1E89370400440532013000",
        "space prefix D E89370400440532013000",
        "ordinary account 370400440532013000",
        "credit-card lookalike 4242424242424242",
        "UUID 550e8400-e29b-41d4-a716-446655440000",
        "hex digest DE89370400440532013000ABCDEF",
        "template {{iban}}",
        "template <bank-account>",
        "documentation says IBAN without a value",
        "country only DE",
        "empty value IBAN=",
        "spaces only DE89                    ",
        "invalid print tail GB29 NWBK 6016 1331 9268 1X",
        "newline DE89\n3704 0044 0532 0130 00",
    )
    if len(texts) != count:
        raise ValueError("curated IBAN negative count does not match manifest")
    return [
        PIIAccuracyScenario(
            scenario_id=f"curated-iban-negative-{index:04d}",
            category="curated_iban_negative",
            text=text,
            expected=(),
        )
        for index, text in enumerate(texts)
    ]


def _curated_negative_scenarios(count: int) -> list[PIIAccuracyScenario]:
    """Return explicit realistic lookalikes that must remain unchanged."""

    texts = (
        "mailbox alice@example",
        "mailbox alice@localhost",
        "mailbox .alice@example.com",
        "mailbox alice.@example.com",
        "mailbox alice..smith@example.com",
        "mailbox alice@example..com",
        "mailbox alice@-example.com",
        "mailbox alice@example-.com",
        "mailbox alice@example.c",
        "mailbox alice@example.123",
        "mailbox alice@exam_ple.com",
        "mailbox a@b.com@c.com",
        "mailbox éAlice@example.com",
        "mailbox alice@example.comé",
        "mailbox alice@example.com_suffix",
        'mailbox "alice smith"@example.com',
        "mailbox alice@[999.0.2.1]",
        "mailbox alice＠example.com",
        "mailbox alice@exаmple.com",
        "mailbox alice@\u200bexample.com",
        "mailbox user_at_example_dot_com",
        "mailbox @example.com",
        "mailbox alice@.example.com",
        "mailbox alice@example.com-embedded",
        "invalid IPv4 999.1.1.1",
        "invalid IPv4 192.168.1.999",
        "noncanonical IPv4 01.2.3.4",
        "short IPv4 1.2.3",
        "long IPv4 1.2.3.4.5",
        "embedded host192.168.1.1",
        "embedded 192.168.1.1host",
        "hyphenated host-192.168.1.1",
        "hyphenated 192.168.1.1-host",
        "invalid IPv4 256.256.256.256",
        "invalid IPv4 192.0.2.-1",
        "spaced IPv4 192 . 0 . 2 . 1",
        "comma IPv4 192,0,2,1",
        "release 1.2.3-beta",
        "release 2026.08.17",
        "decimal 1234.5678",
        "clock 12:34:56",
        "partial MAC aa:bb:cc:dd:ee",
        "UUID 550e8400-e29b-41d4-a716-446655440000",
        "invalid IPv6 2001:db8:::1",
        "short IPv6 2001:db8:1",
        "invalid IPv6 2001:db8::gggg",
        "zone IPv6 fe80:::1%eth0",
        "embedded host2001:db8::1",
        "embedded 2001:db8::1host",
        "too many groups 2001:db8:1:2:3:4:5:6:7",
        "multiple compression 2001:db8::1::2",
        "trailing colon 2001:db8:0:1:1:1:1:1:",
        "leading colon :::2001:db8:0:1:1:1:1:1",
        "IPv4 suffix 192.0.2.1.example",
        "IPv4 prefix build-192.0.2.1",
        "fullwidth digits １９２.０.２.１",
        "Arabic digits ١٩٢.٠.٢.١",
        "documentation says email address without a value",
        "documentation says IPv4 and IPv6 without values",
        "template {{user}}@{{domain}}",
        "template $email_address",
        "template <ip-address>",
        "empty brackets [] and empty mailbox <>",
        "ordinary prose with no identifiers",
    )
    if len(texts) != count:
        raise ValueError("curated negative count does not match manifest")
    return [
        PIIAccuracyScenario(
            scenario_id=f"curated-negative-{index:04d}",
            category="curated_negative",
            text=text,
            expected=(),
        )
        for index, text in enumerate(texts)
    ]


def build_corpus(
    manifest_path: Path = _MANIFEST_PATH,
) -> PIIAccuracyCorpus:
    """Build and verify the committed deterministic corpus definition."""

    if not isinstance(manifest_path, Path):
        raise TypeError("manifest_path must be a pathlib.Path")
    manifest = _load_manifest(manifest_path)
    groups = manifest["groups"]
    if not isinstance(groups, dict):
        raise RuntimeError("validated groups changed type")
    scenarios = [
        *_email_scenarios(groups["email_positive"]),
        *_ip_scenarios(groups["ip_positive"]),
        *_mac_scenarios(groups["mac_positive"]),
        *_iban_scenarios(groups["iban_positive"]),
        *_mixed_scenarios(groups["mixed_positive"]),
        *_negative_scenarios(groups["negative"]),
        *_curated_email_scenarios(groups["curated_email_positive"]),
        *_curated_ip_scenarios(groups["curated_ip_positive"]),
        *_curated_mac_scenarios(groups["curated_mac_positive"]),
        *_curated_mac_negative_scenarios(groups["curated_mac_negative"]),
        *_curated_iban_negative_scenarios(groups["curated_iban_negative"]),
        *_curated_negative_scenarios(groups["curated_negative"]),
    ]
    seed = manifest["seed"]
    if not isinstance(seed, int):
        raise RuntimeError("validated seed changed type")
    random.Random(seed).shuffle(scenarios)
    corpus = PIIAccuracyCorpus(
        dataset_id=str(manifest["dataset_id"]),
        seed=seed,
        uses_llm=bool(manifest["uses_llm"]),
        uses_network=bool(manifest["uses_network"]),
        synthetic_examples_only=bool(manifest["synthetic_examples_only"]),
        scenarios=tuple(scenarios),
    )
    expected_sha256 = manifest["expected_sha256"]
    if expected_sha256 != "PENDING" and corpus.sha256 != expected_sha256:
        raise RuntimeError("PII accuracy corpus digest does not match manifest")
    return corpus


def _expected_redaction(scenario: PIIAccuracyScenario) -> str:
    parts: list[str] = []
    cursor = 0
    for finding in sorted(scenario.expected, key=lambda item: item.start):
        if finding.start < cursor or finding.end > len(scenario.text):
            raise ValueError(
                f"invalid expected span in scenario {scenario.scenario_id}"
            )
        parts.extend((scenario.text[cursor : finding.start], "[REDACTED]"))
        cursor = finding.end
    parts.append(scenario.text[cursor:])
    return "".join(parts)


def evaluate_corpus(
    corpus: PIIAccuracyCorpus,
    *,
    scanner: RuleScanner | None = None,
) -> PIIAccuracyReport:
    """Evaluate exact rule, span, and redaction behavior."""

    if not isinstance(corpus, PIIAccuracyCorpus):
        raise TypeError("corpus must be a PIIAccuracyCorpus")
    if scanner is not None and not isinstance(scanner, RuleScanner):
        raise TypeError("scanner must be a RuleScanner or None")
    active_scanner = scanner or RuleScanner(
        rules=(
            EmailAddressRule(),
            IPAddressRule(),
            MACAddressRule(MACAddressConfig()),
            IBANRule(IBANConfig()),
        )
    )
    expected_by_rule: Counter[str] = Counter()
    actual_by_rule: Counter[str] = Counter()
    true_by_rule: Counter[str] = Counter()
    false_positive_by_rule: Counter[str] = Counter()
    false_negative_by_rule: Counter[str] = Counter()
    scenario_by_category: Counter[str] = Counter()
    expected_by_category: Counter[str] = Counter()
    actual_by_category: Counter[str] = Counter()
    true_by_category: Counter[str] = Counter()
    true_negative_by_category: Counter[str] = Counter()
    false_positive_by_category: Counter[str] = Counter()
    false_negative_by_category: Counter[str] = Counter()
    redaction_failure_by_category: Counter[str] = Counter()
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negative_scenarios = 0
    redaction_failures = 0
    actual_findings = 0
    expected_findings = 0
    for scenario in corpus.scenarios:
        findings = active_scanner.scan(
            scenario.text,
            scope=ScanScope.INPUT,
        )
        expected = {
            (item.rule_id, item.start, item.end) for item in scenario.expected
        }
        actual = {
            (item.rule_id, item.span.start, item.span.end) for item in findings
        }
        shared = expected & actual
        missing = expected - actual
        unexpected = actual - expected
        true_positives += len(shared)
        false_positives += len(unexpected)
        false_negatives += len(missing)
        expected_findings += len(expected)
        actual_findings += len(actual)
        expected_by_rule.update(item[0] for item in expected)
        actual_by_rule.update(item[0] for item in actual)
        true_by_rule.update(item[0] for item in shared)
        false_positive_by_rule.update(item[0] for item in unexpected)
        false_negative_by_rule.update(item[0] for item in missing)
        scenario_by_category[scenario.category] += 1
        expected_by_category[scenario.category] += len(expected)
        actual_by_category[scenario.category] += len(actual)
        true_by_category[scenario.category] += len(shared)
        false_positive_by_category[scenario.category] += len(unexpected)
        false_negative_by_category[scenario.category] += len(missing)
        if not expected and not actual:
            true_negative_scenarios += 1
            true_negative_by_category[scenario.category] += 1
        redaction_failed = active_scanner.redact(
            scenario.text, findings
        ) != _expected_redaction(scenario)
        if redaction_failed:
            redaction_failures += 1
            redaction_failure_by_category[scenario.category] += 1
    discovered_rule_ids = set(expected_by_rule) | set(actual_by_rule)
    rules = tuple(
        RuleAccuracy(
            rule_id=rule_id,
            expected_findings=expected_by_rule[rule_id],
            true_positives=true_by_rule[rule_id],
            false_positives=false_positive_by_rule[rule_id],
            false_negatives=false_negative_by_rule[rule_id],
        )
        for rule_id in sorted(discovered_rule_ids)
    )
    categories = tuple(
        CategoryAccuracy(
            category=category,
            scenario_count=scenario_by_category[category],
            expected_findings=expected_by_category[category],
            actual_findings=actual_by_category[category],
            true_positives=true_by_category[category],
            true_negative_scenarios=true_negative_by_category[category],
            false_positives=false_positive_by_category[category],
            false_negatives=false_negative_by_category[category],
            redaction_failures=redaction_failure_by_category[category],
        )
        for category in sorted(scenario_by_category)
    )
    return PIIAccuracyReport(
        dataset_id=corpus.dataset_id,
        corpus_sha256=corpus.sha256,
        scenario_count=len(corpus.scenarios),
        expected_findings=expected_findings,
        actual_findings=actual_findings,
        true_positives=true_positives,
        true_negative_scenarios=true_negative_scenarios,
        false_positives=false_positives,
        false_negatives=false_negatives,
        redaction_failures=redaction_failures,
        rules=rules,
        categories=categories,
    )


def write_corpus(
    corpus: PIIAccuracyCorpus,
    output_directory: Path,
) -> tuple[Path, Path]:
    """Write an optional generated JSONL corpus and disclosure-safe manifest."""

    if not isinstance(corpus, PIIAccuracyCorpus):
        raise TypeError("corpus must be a PIIAccuracyCorpus")
    if not isinstance(output_directory, Path):
        raise TypeError("output_directory must be a pathlib.Path")
    output_directory.mkdir(parents=True, exist_ok=True)
    corpus_path = output_directory / "pii_accuracy_corpus.jsonl"
    manifest_path = output_directory / "pii_accuracy_generated_manifest.json"
    lines = [
        json.dumps(
            {
                "scenario_id": scenario.scenario_id,
                "category": scenario.category,
                "text": scenario.text,
                "expected": [
                    {
                        "rule_id": finding.rule_id,
                        "start": finding.start,
                        "end": finding.end,
                    }
                    for finding in scenario.expected
                ],
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        for scenario in corpus.scenarios
    ]
    corpus_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest_path.write_text(
        json.dumps(
            {
                "dataset_id": corpus.dataset_id,
                "seed": corpus.seed,
                "scenario_count": len(corpus.scenarios),
                "expected_finding_count": sum(
                    len(item.expected) for item in corpus.scenarios
                ),
                "category_counts": dict(
                    sorted(
                        Counter(
                            item.category for item in corpus.scenarios
                        ).items()
                    )
                ),
                "sha256": corpus.sha256,
                "uses_llm": corpus.uses_llm,
                "uses_network": corpus.uses_network,
                "synthetic_examples_only": corpus.synthetic_examples_only,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return corpus_path, manifest_path


__all__ = [
    "ExpectedPIIFinding",
    "CategoryAccuracy",
    "PIIAccuracyCorpus",
    "PIIAccuracyReport",
    "PIIAccuracyScenario",
    "RuleAccuracy",
    "build_corpus",
    "evaluate_corpus",
    "write_corpus",
]
