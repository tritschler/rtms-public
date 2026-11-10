"""
test_redpanda_connect_audit.py - Unit tests for Redpanda Connect Version Compliance Audit (CVE-2026-123270).
"""

from plugins.redpanda_connect.redpanda_connect_cve_2026_123270_audit import (
    RedpandaConnectAuditPlugin,
    parse_redpanda_connect_version,
    is_redpanda_connect_version_vulnerable,
)


def test_plugin_metadata():
    plugin = RedpandaConnectAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-123270"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Redpanda Connect" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_redpanda_connect_version('{"version":"v4.105.0","built":"2026-10-01T00:00:00Z"}') == (
        4,
        105,
        0,
        "4.105.0",
    )
    assert parse_redpanda_connect_version("Redpanda Connect v4.111.0") == (4, 111, 0, "4.111.0")
    assert parse_redpanda_connect_version("envoy/1.28.0") is None


def test_version_vulnerability_logic():
    vuln_4105, reason_4105 = is_redpanda_connect_version_vulnerable(4, 105, 0)
    assert vuln_4105 is True
    assert "CVE-2026-123270" in reason_4105

    vuln_4110, _ = is_redpanda_connect_version_vulnerable(4, 110, 2)
    assert vuln_4110 is True

    safe_4111, reason_4111 = is_redpanda_connect_version_vulnerable(4, 111, 0)
    assert safe_4111 is False
    assert "4.111.0" in reason_4111

    safe_old, _ = is_redpanda_connect_version_vulnerable(4, 30, 0)
    assert safe_old is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = RedpandaConnectAuditPlugin()
    mocker.patch.object(
        plugin,
        "probe_http_endpoint",
        return_value={
            "port": 4195,
            "path": "/version",
            "status_code": 200,
            "headers": {"content-type": "application/json"},
            "body_snippet": '{"version":"v4.108.0","built":"2026-10-20T12:00:00Z"}',
        },
    )

    hit = plugin.inspect_target_port("10.0.0.82", 4195)
    assert hit is not None
    assert hit["service_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "4.108.0"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = RedpandaConnectAuditPlugin()
    plugin.discovered_ports = [4195]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 4195,
            "service_detected": True,
            "version": "4.108.0",
            "source": "Redpanda Connect /version endpoint",
            "is_vulnerable": True,
            "reason": "Affected 4.39 to 4.110",
        },
    )
    res = plugin.run_audit("10.0.0.82", [4195])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-123270" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 4195,
            "service_detected": True,
            "version": "4.111.0",
            "source": "Redpanda Connect /version endpoint",
            "is_vulnerable": False,
            "reason": "Patched >= 4.111.0",
        },
    )
    res_safe = plugin.run_audit("10.0.0.82", [4195])
    assert res_safe["status"] == "OK"
