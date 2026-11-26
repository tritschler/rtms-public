"""
test_hpe_airwave_audit.py - Unit tests for HPE Networking Management Software (AirWave)
Multi-CVE Compliance Audit (CVE-2026-133971, CVE-2026-133972, CVE-2026-133973).
"""

from plugins.hpe_airwave.hpe_airwave_cve_2026_133973_audit import (
    HPEAirWaveAuditPlugin,
    parse_hpe_airwave_version,
    is_hpe_airwave_version_vulnerable,
)


def test_plugin_metadata():
    plugin = HPEAirWaveAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-133973"
    assert plugin.info["severity"] == "CRITICAL"
    assert "AirWave" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    html = "<footer>HPE Networking Management Software (AirWave) 8.3.0.7</footer>"
    assert parse_hpe_airwave_version(html) == (8, 3, 0, 7, "8.3.0.7")

    xml = "<amp_version>8.3.0.8</amp_version>"
    assert parse_hpe_airwave_version(xml) == (8, 3, 0, 8, "8.3.0.8")
    assert parse_hpe_airwave_version("nginx/1.26.0") is None


def test_version_vulnerability_logic():
    vuln, reason = is_hpe_airwave_version_vulnerable(8, 3, 0, 7, "8.3.0.7")
    assert vuln is True
    assert "CVE-2026-133971" in reason
    assert "CVE-2026-133972" in reason
    assert "CVE-2026-133973" in reason

    safe, _ = is_hpe_airwave_version_vulnerable(8, 3, 0, 8, "8.3.0.8")
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = HPEAirWaveAuditPlugin()
    plugin.discovered_ports = [443]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "8.3.0.7",
            "source": "HPE AirWave Web Login Page",
            "is_vulnerable": True,
            "reason": "Affected <= 8.3.0.7",
        },
    )
    res = plugin.run_audit("10.0.0.62", [443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-133973" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "8.3.0.8",
            "source": "HPE AirWave Web Login Page",
            "is_vulnerable": False,
            "reason": "Patched >= 8.3.0.8",
        },
    )
    res_safe = plugin.run_audit("10.0.0.62", [443])
    assert res_safe["status"] == "OK"
