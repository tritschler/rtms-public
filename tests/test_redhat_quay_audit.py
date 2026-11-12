"""
test_redhat_quay_audit.py - Unit tests for Red Hat Quay Version Compliance Audit (CVE-2026-110697 / CVE-2026-123710).
"""

from plugins.redhat_quay.redhat_quay_cve_2026_110697_audit import (
    RedHatQuayAuditPlugin,
    parse_quay_version,
    is_quay_version_vulnerable,
)


def test_plugin_metadata():
    plugin = RedHatQuayAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-110697"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Red Hat Quay" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_quay_version("Red Hat Quay v3.16.3") == (3, 16, 3, "3.16.3")
    assert parse_quay_version('{"version": "v3.18.1"}') == (3, 18, 1, "3.18.1")
    assert parse_quay_version('window.quay_version = "3.14.5";') == (3, 14, 5, "3.14.5")
    assert parse_quay_version("Harbor v2.10.0") is None


def test_version_vulnerability_logic():
    vuln_310, _ = is_quay_version_vulnerable(3, 10, 5)
    assert vuln_310 is True

    vuln_312, reason_312 = is_quay_version_vulnerable(3, 12, 10)
    assert vuln_312 is True
    assert "CVE-2026-110697" in reason_312

    safe_312, _ = is_quay_version_vulnerable(3, 12, 11)
    assert safe_312 is False

    vuln_316, _ = is_quay_version_vulnerable(3, 16, 3)
    assert vuln_316 is True

    safe_316, _ = is_quay_version_vulnerable(3, 16, 4)
    assert safe_316 is False

    vuln_318, _ = is_quay_version_vulnerable(3, 18, 1)
    assert vuln_318 is True

    safe_318, _ = is_quay_version_vulnerable(3, 18, 2)
    assert safe_318 is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = RedHatQuayAuditPlugin()
    mocker.patch.object(
        plugin,
        "probe_http_endpoint",
        return_value={
            "port": 443,
            "path": "/api/v1/discovery",
            "status_code": 200,
            "headers": {"server": "gunicorn"},
            "body_snippet": '{"service": "Red Hat Quay", "version": "v3.18.1"}',
        },
    )

    hit = plugin.inspect_target_port("10.0.0.30", 443)
    assert hit is not None
    assert hit["service_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "3.18.1"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = RedHatQuayAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "3.18.1",
            "source": "Red Hat Quay /api/v1/discovery endpoint",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-110697",
        },
    )
    res = plugin.run_audit("10.0.0.30", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-110697" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "3.18.2",
            "source": "Red Hat Quay /api/v1/discovery endpoint",
            "is_vulnerable": False,
            "reason": "Patched >= 3.18.2",
        },
    )
    res_safe = plugin.run_audit("10.0.0.30", [443])
    assert res_safe["status"] == "OK"
