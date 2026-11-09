"""
test_openemr_audit.py - Unit tests for OpenEMR Version Compliance Audit (CVE-2026-124445 / CVE-2026-124490).
"""

from plugins.openemr.openemr_cve_2026_124445_audit import (
    OpenEMRAuditPlugin,
    parse_openemr_version,
    is_openemr_version_vulnerable,
)


def test_plugin_metadata():
    plugin = OpenEMRAuditPlugin()
    assert "CVE-2026-124445" in plugin.info["cve"]
    assert "CVE-2026-124490" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "OpenEMR" in plugin.info["name"]


def test_version_parsing():
    assert parse_openemr_version("<td>v8.2.0 (1)</td>") == (8, 2, 0, "8.2.0")
    assert parse_openemr_version("OpenEMR v8.3.0") == (8, 3, 0, "8.3.0")
    assert parse_openemr_version("Version: 8.4.0") == (8, 4, 0, "8.4.0")
    assert parse_openemr_version("<html>Welcome</html>") is None


def test_version_vulnerability_logic():
    vuln_82, reason_82 = is_openemr_version_vulnerable(8, 2, 0)
    assert vuln_82 is True
    assert "CVE-2026-124490" in reason_82
    assert "CVE-2026-124445" in reason_82

    vuln_83, reason_83 = is_openemr_version_vulnerable(8, 3, 1)
    assert vuln_83 is True
    assert "CVE-2026-124445" in reason_83
    assert "CVE-2026-124490" not in reason_83

    vuln_84, reason_84 = is_openemr_version_vulnerable(8, 4, 0)
    assert vuln_84 is False
    assert "patched" in reason_84


def test_inspect_target_port_vulnerable(mocker):
    plugin = OpenEMRAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "path": "/interface/login/login.php",
        "status_code": 200,
        "headers": {},
        "body_snippet": "<html><title>OpenEMR Login</title><div>OpenEMR v8.2.0</div></html>",
    })

    hit = plugin.inspect_target_port("10.0.0.50", 443)
    assert hit is not None
    assert hit["service_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "8.2.0"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = OpenEMRAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "service_detected": True,
        "version": "8.2.0",
        "source": "OpenEMR Login Page",
        "is_vulnerable": True,
        "reason": "Affected by CVE-2026-124445, CVE-2026-124490",
    })
    res = plugin.run_audit("10.0.0.50", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-124445" in res["proof"]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 443,
        "service_detected": True,
        "version": "8.4.0",
        "source": "OpenEMR Login Page",
        "is_vulnerable": False,
        "reason": "Patched >= 8.4.0",
    })
    res_safe = plugin.run_audit("10.0.0.50", [443])
    assert res_safe["status"] == "OK"
