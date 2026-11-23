"""
test_cribl_stream_audit.py - Unit tests for Cribl Stream REST Collector Pagination
Compliance Audit (CVE-2026-115899).
"""

from plugins.cribl_stream.cribl_stream_cve_2026_115899_audit import (
    CriblStreamAuditPlugin,
    parse_cribl_stream_version,
    is_cribl_stream_version_vulnerable,
)


def test_plugin_metadata():
    plugin = CriblStreamAuditPlugin()
    assert "CVE-2026-115899" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Cribl Stream" in plugin.info["name"]


def test_version_parsing():
    assert parse_cribl_stream_version('{"BUILD":{"VERSION":"4.20.4-f8a1b2c"}}') == (4, 20, 4, "4.20.4")
    assert parse_cribl_stream_version("X-Cribl-Version: 4.20.5") == (4, 20, 5, "4.20.5")
    assert parse_cribl_stream_version("<html>Not cribl</html>") is None


def test_version_vulnerability_logic():
    vuln, reason = is_cribl_stream_version_vulnerable(4, 20, 4)
    assert vuln is True
    assert "CVE-2026-115899" in reason

    safe, _ = is_cribl_stream_version_vulnerable(4, 20, 5)
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = CriblStreamAuditPlugin()
    plugin.discovered_ports = [9000]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 9000,
            "service_detected": True,
            "version": "4.20.4",
            "source": "Cribl Stream System Info Endpoint (/api/v1/system/info)",
            "is_vulnerable": True,
            "reason": "Affected <= 4.20.4 (< 4.20.5)",
        },
    )
    res = plugin.run_audit("10.0.0.70", [9000])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-115899" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 9000,
            "service_detected": True,
            "version": "4.20.5",
            "source": "Cribl Stream System Info Endpoint (/api/v1/system/info)",
            "is_vulnerable": False,
            "reason": "Patched >= 4.20.5",
        },
    )
    res_safe = plugin.run_audit("10.0.0.70", [9000])
    assert res_safe["status"] == "OK"
