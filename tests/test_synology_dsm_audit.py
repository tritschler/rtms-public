"""
test_synology_dsm_audit.py - Unit tests for Synology DiskStation Manager (DSM) Version Compliance Audit (CVE-2026-76954).
"""

from plugins.synology_dsm.synology_dsm_cve_2026_76954_audit import (
    SynologyDSMAuditPlugin,
    parse_synology_dsm_version,
    is_synology_dsm_version_vulnerable,
)


def test_plugin_metadata():
    plugin = SynologyDSMAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-76954"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Synology" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_synology_dsm_version("Synology DSM 7.2.1-69057-12") == (
        7,
        2,
        1,
        69057,
        12,
        "7.2.1-69057-12",
    )
    assert parse_synology_dsm_version("DSM 7.2.2-72806 Update 9") == (
        7,
        2,
        2,
        72806,
        9,
        "7.2.2-72806-9",
    )
    assert parse_synology_dsm_version("v=7.4.1-90080") == (
        7,
        4,
        1,
        90080,
        0,
        "7.4.1-90080-0",
    )
    assert parse_synology_dsm_version("Apache/2.4.58") is None


def test_version_vulnerability_logic():
    vuln_721, reason_721 = is_synology_dsm_version_vulnerable(7, 2, 1, 69057, 12)
    assert vuln_721 is True
    assert "CVE-2026-76954" in reason_721

    safe_721, _ = is_synology_dsm_version_vulnerable(7, 2, 1, 69057, 13)
    assert safe_721 is False

    vuln_722, _ = is_synology_dsm_version_vulnerable(7, 2, 2, 72806, 9)
    assert vuln_722 is True

    safe_722, _ = is_synology_dsm_version_vulnerable(7, 2, 2, 72806, 10)
    assert safe_722 is False

    vuln_732, _ = is_synology_dsm_version_vulnerable(7, 3, 2, 86009, 4)
    assert vuln_732 is True

    safe_732, _ = is_synology_dsm_version_vulnerable(7, 3, 2, 86009, 5)
    assert safe_732 is False

    vuln_741, _ = is_synology_dsm_version_vulnerable(7, 4, 1, 90080, 0)
    assert vuln_741 is True

    safe_741, _ = is_synology_dsm_version_vulnerable(7, 4, 1, 90080, 1)
    assert safe_741 is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = SynologyDSMAuditPlugin()
    mocker.patch.object(
        plugin,
        "probe_http_endpoint",
        return_value={
            "port": 5000,
            "path": "/webman/index.cgi",
            "status_code": 200,
            "headers": {"server": "nginx"},
            "body_snippet": '<html><title>Synology DiskStation</title><script src="sds.js?v=7.2.2-72806-9"></script></html>',
        },
    )

    hit = plugin.inspect_target_port("10.0.0.20", 5000)
    assert hit is not None
    assert hit["service_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "7.2.2-72806-9"


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = SynologyDSMAuditPlugin()
    plugin.discovered_ports = [5000]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 5000,
            "service_detected": True,
            "version": "7.2.2-72806-9",
            "source": "Synology DSM /webman/index.cgi desktop portal",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-76954",
        },
    )
    res = plugin.run_audit("10.0.0.20", [5000])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-76954" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 5000,
            "service_detected": True,
            "version": "7.2.2-72806-10",
            "source": "Synology DSM /webman/index.cgi desktop portal",
            "is_vulnerable": False,
            "reason": "Patched >= 7.2.2-72806-10",
        },
    )
    res_safe = plugin.run_audit("10.0.0.20", [5000])
    assert res_safe["status"] == "OK"
