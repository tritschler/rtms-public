"""
test_sharepoint_audit.py - Unit tests for Microsoft SharePoint Server Version Compliance Audit (CVE-2026-120002).
"""

from plugins.sharepoint.sharepoint_cve_2026_120002_audit import (
    SharePointAuditPlugin,
    parse_sharepoint_version,
    is_sharepoint_version_vulnerable,
)


def test_plugin_metadata():
    plugin = SharePointAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-120002"
    assert plugin.info["severity"] == "CRITICAL"
    assert "SharePoint" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_sharepoint_version("16.0.18526.20400") == (16, 0, 18526, 20400, "16.0.18526.20400")
    assert parse_sharepoint_version("MicrosoftSharePointTeamServices: 16.0.0.10416") == (
        16,
        0,
        10416,
        0,
        "16.0.0.10416",
    )
    assert parse_sharepoint_version("15.0.0.5589") == (15, 0, 5589, 0, "15.0.0.5589")
    assert parse_sharepoint_version("nginx/1.24.0") is None


def test_version_vulnerability_logic():
    vuln_sub, reason_sub = is_sharepoint_version_vulnerable(16, 0, 18526, 20400)
    assert vuln_sub is True
    assert "CVE-2026-120002" in reason_sub

    safe_sub, _ = is_sharepoint_version_vulnerable(16, 0, 18526, 20650)
    assert safe_sub is False

    vuln_2019, _ = is_sharepoint_version_vulnerable(16, 0, 10416, 20000)
    assert vuln_2019 is True

    safe_2019, _ = is_sharepoint_version_vulnerable(16, 0, 10417, 20075)
    assert safe_2019 is False

    vuln_2016, _ = is_sharepoint_version_vulnerable(16, 0, 5400, 1000)
    assert vuln_2016 is True

    safe_2016, _ = is_sharepoint_version_vulnerable(16, 0, 5580, 1000)
    assert safe_2016 is False

    vuln_2013, _ = is_sharepoint_version_vulnerable(15, 0, 5589, 1000)
    assert vuln_2013 is True


def test_inspect_target_port_vulnerable(mocker):
    plugin = SharePointAuditPlugin()
    mocker.patch.object(
        plugin,
        "probe_http_endpoint",
        return_value={
            "port": 443,
            "path": "/",
            "status_code": 200,
            "headers": {"microsoftsharepointteamservices": "16.0.18526.20400"},
            "body_snippet": "<html>SharePoint Site</html>",
        },
    )

    hit = plugin.inspect_target_port("10.0.0.70", 443)
    assert hit is not None
    assert hit["service_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "16.0.18526.20400"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = SharePointAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "16.0.18526.20400",
            "source": "SharePoint root HTTP response (MicrosoftSharePointTeamServices header)",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-120002",
        },
    )
    res = plugin.run_audit("10.0.0.70", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-120002" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "16.0.18526.20650",
            "source": "SharePoint root HTTP response (MicrosoftSharePointTeamServices header)",
            "is_vulnerable": False,
            "reason": "Patched >= 16.0.18526.20650",
        },
    )
    res_safe = plugin.run_audit("10.0.0.70", [443])
    assert res_safe["status"] == "OK"
