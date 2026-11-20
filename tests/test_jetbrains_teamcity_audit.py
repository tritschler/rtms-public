"""
test_jetbrains_teamcity_audit.py - Unit tests for JetBrains TeamCity Version Compliance Audit
(CVE-2026-132234, CVE-2026-132233, CVE-2026-132232, CVE-2026-132231, CVE-2026-132891).
"""

from plugins.jetbrains_teamcity.jetbrains_teamcity_cve_2026_132234_audit import (
    JetBrainsTeamCityAuditPlugin,
    parse_teamcity_version,
    is_teamcity_version_vulnerable,
)


def test_plugin_metadata():
    plugin = JetBrainsTeamCityAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-132234"
    assert plugin.info["severity"] == "CRITICAL"
    assert "TeamCity" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_teamcity_version("TeamCity Enterprise 2026.1.2 (build 197550)") == (
        2026,
        1,
        2,
        "2026.1.2",
    )
    assert parse_teamcity_version('<span class="vWord">Version</span> 2025.11.5') == (
        2025,
        11,
        5,
        "2025.11.5",
    )
    assert parse_teamcity_version("Jenkins 2.479.1") is None


def test_version_vulnerability_logic():
    vuln_2025, reason = is_teamcity_version_vulnerable(2025, 11, 5, "2025.11.5")
    assert vuln_2025 is True
    assert "CVE-2026-132234" in reason
    assert "CVE-2026-132231" in reason
    assert "CVE-2026-132891" in reason

    vuln_2025_7, reason_2025_7 = is_teamcity_version_vulnerable(2025, 11, 7, "2025.11.7")
    assert vuln_2025_7 is True
    assert "CVE-2026-132891" in reason_2025_7

    vuln_2026, _ = is_teamcity_version_vulnerable(2026, 1, 2, "2026.1.2")
    assert vuln_2026 is True

    vuln_2026_3, reason_2026_3 = is_teamcity_version_vulnerable(2026, 1, 3, "2026.1.3")
    assert vuln_2026_3 is True
    assert "CVE-2026-132891" in reason_2026_3

    safe_2025, _ = is_teamcity_version_vulnerable(2025, 11, 8, "2025.11.8")
    assert safe_2025 is False

    safe_2026, _ = is_teamcity_version_vulnerable(2026, 1, 4, "2026.1.4")
    assert safe_2026 is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = JetBrainsTeamCityAuditPlugin()
    plugin.discovered_ports = [8111]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8111,
            "service_detected": True,
            "version": "2026.1.3",
            "source": "TeamCity Web Login Page",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-132891",
        },
    )
    res = plugin.run_audit("10.0.0.81", [8111])
    assert res["status"] == "Vulnerable"
    assert "2026.1.3" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8111,
            "service_detected": True,
            "version": "2026.1.4",
            "source": "TeamCity Web Login Page",
            "is_vulnerable": False,
            "reason": "Patched >= 2026.1.4",
        },
    )
    res_safe = plugin.run_audit("10.0.0.81", [8111])
    assert res_safe["status"] == "OK"
