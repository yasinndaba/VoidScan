"""Table-driven tests for the central severity policy."""

import pytest
from voidscan import findings, severity
from voidscan.severity import (
    ANALYZER_SEVERITIES,
    DATABASE_RULE,
    DIRECTORY_SEVERITY,
    DISCOVERY_SEVERITY,
    FTP_RULE,
    GENERIC_RULE,
    HTTP_RULE,
    HTTPS_RULE,
    IP_INFO_SEVERITY,
    PORT_RULES,
    RDP_RULE,
    REDIS_RULE,
    SERVICE_RULES,
    SEVERITY_COLORS,
    SEVERITY_ORDER,
    SEVERITY_RANK,
    SMB_RULE,
    SSH_RULE,
    SUBDOMAIN_SEVERITY,
    TELNET_RULE,
    VNC_RULE,
    ServiceRule,
    Severity,
    rule_for_service,
)

ALL_RULES = [
    SSH_RULE,
    HTTP_RULE,
    HTTPS_RULE,
    FTP_RULE,
    TELNET_RULE,
    SMB_RULE,
    RDP_RULE,
    VNC_RULE,
    REDIS_RULE,
    DATABASE_RULE,
    GENERIC_RULE,
]

SERVICE_EXPECTATIONS = [
    (22, "ssh", SSH_RULE, Severity.INFO),
    (80, "http", HTTP_RULE, Severity.INFO),
    (443, "https", HTTPS_RULE, Severity.INFO),
    (443, "ssl/https", HTTPS_RULE, Severity.INFO),
    (443, "ssl/http", HTTP_RULE, Severity.INFO),
    (21, "ftp", FTP_RULE, Severity.MEDIUM),
    (23, "telnet", TELNET_RULE, Severity.HIGH),
    (445, "microsoft-ds", SMB_RULE, Severity.MEDIUM),
    (139, "netbios-ssn", SMB_RULE, Severity.MEDIUM),
    (445, "smb", SMB_RULE, Severity.MEDIUM),
    (3389, "ms-wbt-server", RDP_RULE, Severity.MEDIUM),
    (3389, "rdp", RDP_RULE, Severity.MEDIUM),
    (5900, "vnc", VNC_RULE, Severity.MEDIUM),
    (3306, "mysql", DATABASE_RULE, Severity.MEDIUM),
    (5432, "postgresql", DATABASE_RULE, Severity.MEDIUM),
    (1433, "ms-sql-s", DATABASE_RULE, Severity.MEDIUM),
    (27017, "mongodb", DATABASE_RULE, Severity.MEDIUM),
    (6379, "redis", REDIS_RULE, Severity.HIGH),
]

PORT_EXPECTATIONS = [
    (21, FTP_RULE, Severity.MEDIUM),
    (23, TELNET_RULE, Severity.HIGH),
    (139, SMB_RULE, Severity.MEDIUM),
    (445, SMB_RULE, Severity.MEDIUM),
    (1433, DATABASE_RULE, Severity.MEDIUM),
    (3306, DATABASE_RULE, Severity.MEDIUM),
    (3389, RDP_RULE, Severity.MEDIUM),
    (5432, DATABASE_RULE, Severity.MEDIUM),
    (5900, VNC_RULE, Severity.MEDIUM),
    (6379, REDIS_RULE, Severity.HIGH),
    (27017, DATABASE_RULE, Severity.MEDIUM),
]

ANALYZER_EXPECTATIONS = [
    ("discovery", DISCOVERY_SEVERITY, Severity.INFO),
    ("subdomains", SUBDOMAIN_SEVERITY, Severity.INFO),
    ("directories", DIRECTORY_SEVERITY, Severity.INFO),
    ("ip_info", IP_INFO_SEVERITY, Severity.INFO),
]


@pytest.mark.parametrize(
    ("port", "service", "expected_rule", "expected_severity"),
    SERVICE_EXPECTATIONS,
)
def test_service_rules_map_to_expected_severity(
    port: int,
    service: str,
    expected_rule: ServiceRule,
    expected_severity: Severity,
) -> None:
    rule = rule_for_service(port, service)

    assert rule is expected_rule
    assert rule.severity is expected_severity


@pytest.mark.parametrize(
    ("port", "expected_rule", "expected_severity"),
    PORT_EXPECTATIONS,
)
def test_port_fallback_maps_to_expected_severity(
    port: int,
    expected_rule: ServiceRule,
    expected_severity: Severity,
) -> None:
    rule = rule_for_service(port, "unknown")

    assert rule is expected_rule
    assert rule.severity is expected_severity


def test_unknown_port_and_service_use_generic_rule() -> None:
    assert rule_for_service(65000, "unknown") is GENERIC_RULE
    assert GENERIC_RULE.severity is Severity.INFO


def test_service_prefix_takes_precedence_over_port() -> None:
    assert rule_for_service(21, "ssh") is SSH_RULE


def test_https_is_matched_before_http() -> None:
    assert rule_for_service(443, "https") is HTTPS_RULE


def test_every_rule_is_complete() -> None:
    for rule in ALL_RULES:
        assert isinstance(rule, ServiceRule)
        assert rule.title
        assert rule.description
        assert rule.recommendation
        assert isinstance(rule.severity, Severity)


def test_rule_tables_only_reference_known_rules() -> None:
    for _, rule in SERVICE_RULES:
        assert rule in ALL_RULES

    for rule in PORT_RULES.values():
        assert rule in ALL_RULES


def test_severity_order_is_complete_and_most_severe_first() -> None:
    assert list(SEVERITY_ORDER) == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    assert set(SEVERITY_ORDER) == set(Severity)
    assert set(SEVERITY_RANK) == {member.value for member in Severity}
    assert set(SEVERITY_COLORS) == {member.value for member in Severity}


def test_severity_rank_follows_display_order() -> None:
    assert list(SEVERITY_RANK.values()) == list(range(len(SEVERITY_ORDER)))

    for index, member in enumerate(SEVERITY_ORDER):
        assert SEVERITY_RANK[member.value] == index


@pytest.mark.parametrize(
    ("analyzer", "constant", "expected"),
    ANALYZER_EXPECTATIONS,
)
def test_analyzer_severities_are_centralized(
    analyzer: str,
    constant: Severity,
    expected: Severity,
) -> None:
    assert constant is expected
    assert ANALYZER_SEVERITIES[analyzer] is expected


def test_findings_re_exports_the_shared_severity_enum() -> None:
    assert findings.Severity is severity.Severity
