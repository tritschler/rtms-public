"""
test_watchguard_fireware_audit.py - Unit tests for WatchGuard Fireware OS & SonicWall SMA1000 Compliance Audit (CVE-2026-93866).
"""

from plugins.watchguard_fireware.watchguard_fireware_cve_2026_93866_audit import (
    WatchGuardSonicWallVpnAuditPlugin,
    parse_fireware_or_sma_version,
    is_vpn_appliance_vulnerable,
)


def test_plugin_metadata():
    plugin = WatchGuardSonicWallVpnAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-93866"
    assert plugin.info["severity"] == "CRITICAL"
    assert "WatchGuard" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_fireware_or_sma_version("WatchGuard Fireware v12.11.2") == (
        "watchguard",
        12,
        11,
        2,
        "12.11.2",
    )
    assert parse_fireware_or_sma_version("SonicWall SMA 1000 12.4.2") == (
        "sonicwall_sma",
        12,
        4,
        2,
        "12.4.2",
    )
    assert parse_fireware_or_sma_version("Apache/2.4.58") is None


def test_version_vulnerability_logic():
    vuln_wg12, reason_wg12 = is_vpn_appliance_vulnerable("watchguard", 12, 11, 2)
    assert vuln_wg12 is True
    assert "CVE-2026-93866" in reason_wg12

    safe_wg12, _ = is_vpn_appliance_vulnerable("watchguard", 12, 11, 4)
    assert safe_wg12 is False

    vuln_sma, reason_sma = is_vpn_appliance_vulnerable("sonicwall_sma", 12, 4, 2)
    assert vuln_sma is True
    assert "CVE-2026-83548" in reason_sma

    safe_sma, _ = is_vpn_appliance_vulnerable("sonicwall_sma", 12, 4, 3)
    assert safe_sma is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = WatchGuardSonicWallVpnAuditPlugin()
    plugin.discovered_ports = [8080]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "vendor": "watchguard",
            "version": "12.11.2",
            "source": "WatchGuard Firebox Web UI / Auth Portal",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-93866",
        },
    )
    res = plugin.run_audit("10.0.0.30", [8080])
    assert res["status"] == "Vulnerable"
    assert "12.11.2" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "vendor": "watchguard",
            "version": "12.11.4",
            "source": "WatchGuard Firebox Web UI / Auth Portal",
            "is_vulnerable": False,
            "reason": "Patched >= 12.11.4",
        },
    )
    res_safe = plugin.run_audit("10.0.0.30", [8080])
    assert res_safe["status"] == "OK"
