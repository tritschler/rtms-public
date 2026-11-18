"""
test_oracle_weblogic_audit.py - Unit tests for Oracle WebLogic Server Version Compliance Audit
(CVE-2026-91569, CVE-2026-91570, CVE-2026-91583, CVE-2026-91585, CVE-2026-91470, CVE-2026-91456, CVE-2026-91469).
"""

from plugins.oracle_weblogic.oracle_weblogic_cve_2026_91569_audit import (
    OracleWebLogicAuditPlugin,
    parse_weblogic_version,
    is_weblogic_version_vulnerable,
)


def test_plugin_metadata():
    plugin = OracleWebLogicAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-91569"
    assert plugin.info["severity"] == "CRITICAL"
    assert "WebLogic" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_weblogic_version("WebLogic Server 14.1.1.0.0") == (
        14,
        1,
        1,
        0,
        None,
        "14.1.1.0.0",
    )
    assert parse_weblogic_version('<p id="footerVersion">WebLogic Server Version: 12.2.1.4.261117</p>') == (
        12,
        2,
        1,
        4,
        261117,
        "12.2.1.4.261117",
    )
    assert parse_weblogic_version("Apache/2.4.58") is None


def test_version_vulnerability_logic():
    vuln_1411, reason = is_weblogic_version_vulnerable(14, 1, 1, 0, None, "14.1.1.0.0")
    assert vuln_1411 is True
    assert "CVE-2026-91569" in reason
    assert "CVE-2026-91470" in reason

    vuln_1511, _ = is_weblogic_version_vulnerable(15, 1, 1, 0, 260715, "15.1.1.0.260715")
    assert vuln_1511 is True

    safe_psu, _ = is_weblogic_version_vulnerable(14, 1, 2, 0, 261117, "14.1.2.0.261117")
    assert safe_psu is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = OracleWebLogicAuditPlugin()
    plugin.discovered_ports = [7001]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 7001,
            "service_detected": True,
            "version": "14.1.1.0.0",
            "source": "WebLogic Admin Console Login Page",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-91569",
        },
    )
    res = plugin.run_audit("10.0.0.70", [7001])
    assert res["status"] == "Vulnerable"
    assert "14.1.1.0.0" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 7001,
            "service_detected": True,
            "version": "14.1.1.0.261117",
            "source": "WebLogic Admin Console Login Page",
            "is_vulnerable": False,
            "reason": "Patched PSU >= 261117",
        },
    )
    res_safe = plugin.run_audit("10.0.0.70", [7001])
    assert res_safe["status"] == "OK"
