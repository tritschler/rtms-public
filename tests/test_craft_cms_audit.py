"""
test_craft_cms_audit.py - Unit tests for Craft CMS Version Compliance Audit (CVE-2026-115934).
"""

from plugins.craft_cms.craft_cms_cve_2026_115934_audit import (
    CraftCmsAuditPlugin,
    parse_craft_cms_version,
    is_craft_cms_version_vulnerable,
)


def test_plugin_metadata():
    plugin = CraftCmsAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-115934"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Craft CMS" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_craft_cms_version("Craft CMS 4.18.5") == (4, 18, 5, "4.18.5")
    assert parse_craft_cms_version('{"craftVersion":"5.11.0"}') == (5, 11, 0, "5.11.0")
    assert parse_craft_cms_version("Apache/2.4.58") is None


def test_version_vulnerability_logic():
    vuln_v4, reason_v4 = is_craft_cms_version_vulnerable(4, 18, 8)
    assert vuln_v4 is True
    assert "4.18.9" in reason_v4

    safe_v4, _ = is_craft_cms_version_vulnerable(4, 18, 9)
    assert safe_v4 is False

    vuln_v5, reason_v5 = is_craft_cms_version_vulnerable(5, 11, 1)
    assert vuln_v5 is True
    assert "5.11.2" in reason_v5

    safe_v5, _ = is_craft_cms_version_vulnerable(5, 11, 2)
    assert safe_v5 is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = CraftCmsAuditPlugin()
    mocker.patch.object(
        plugin,
        "probe_http_endpoint",
        return_value={
            "port": 443,
            "path": "/admin/login",
            "status_code": 200,
            "headers": {"x-powered-by": "Craft CMS 5.10.3"},
            "body_snippet": "<html><title>Login - Craft CMS</title></html>",
        },
    )

    hit = plugin.inspect_target_port("10.0.0.81", 443)
    assert hit is not None
    assert hit["service_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "5.10.3"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = CraftCmsAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "5.10.3",
            "source": "Craft CMS /admin/login endpoint",
            "is_vulnerable": True,
            "reason": "Affected 5.0.0 before 5.11.2",
        },
    )
    res = plugin.run_audit("10.0.0.81", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-115934" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "5.11.2",
            "source": "Craft CMS /admin/login endpoint",
            "is_vulnerable": False,
            "reason": "Patched >= 5.11.2",
        },
    )
    res_safe = plugin.run_audit("10.0.0.81", [443])
    assert res_safe["status"] == "OK"
