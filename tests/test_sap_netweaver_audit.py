"""
test_sap_netweaver_audit.py - Unit tests for SAP Web Dispatcher & NetWeaver Compliance Audit (CVE-2026-89126).
"""

from plugins.sap_netweaver.sap_netweaver_cve_2026_89126_audit import (
    SapNetWeaverAuditPlugin,
    parse_sap_version,
    is_sap_version_vulnerable,
)


def test_plugin_metadata():
    plugin = SapNetWeaverAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-89126"
    assert plugin.info["severity"] == "CRITICAL"
    assert "SAP" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_sap_version("SAP Web Dispatcher/7.77.0 pl 450") == ("7.77", 450, "7.77 (pl 450)")
    assert parse_sap_version("SAP NetWeaver Application Server / ABAP 753 (Kernel 7.53 Patch 1500)") == (
        "7.53",
        1500,
        "7.53 (pl 1500)",
    )
    assert parse_sap_version("SAP Web Dispatcher/9.20") == ("9.20", None, "9.20")
    assert parse_sap_version("nginx/1.24.0") is None


def test_version_vulnerability_logic():
    vuln_unpatched, reason_unpatched = is_sap_version_vulnerable("7.77", 450)
    assert vuln_unpatched is True
    assert "CVE-2026-89126" in reason_unpatched

    vuln_no_pl, _ = is_sap_version_vulnerable("9.20", None)
    assert vuln_no_pl is True

    vuln_patched, reason_patched = is_sap_version_vulnerable("7.77", 750)
    assert vuln_patched is False
    assert "700" in reason_patched


def test_inspect_target_port_vulnerable(mocker):
    plugin = SapNetWeaverAuditPlugin()
    mocker.patch.object(
        plugin,
        "probe_http_endpoint",
        return_value={
            "port": 44300,
            "path": "/sap/public/ping",
            "status_code": 200,
            "headers": {"server": "SAP Web Dispatcher/7.77.0 pl 420"},
            "body_snippet": "SAP Server is active",
        },
    )

    hit = plugin.inspect_target_port("10.0.0.80", 44300)
    assert hit is not None
    assert hit["service_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "7.77 (pl 420)"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = SapNetWeaverAuditPlugin()
    plugin.discovered_ports = [44300]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 44300,
            "service_detected": True,
            "version": "7.77 (pl 420)",
            "source": "SAP /sap/public/ping status endpoint",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-89126",
        },
    )
    res = plugin.run_audit("10.0.0.80", [44300])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-89126" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 44300,
            "service_detected": True,
            "version": "7.77 (pl 750)",
            "source": "SAP /sap/public/ping status endpoint",
            "is_vulnerable": False,
            "reason": "Patched >= pl 700",
        },
    )
    res_safe = plugin.run_audit("10.0.0.80", [44300])
    assert res_safe["status"] == "OK"
