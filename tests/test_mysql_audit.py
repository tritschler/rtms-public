"""
test_mysql_audit.py - Unit tests for Oracle MySQL Server & Cluster Version Compliance Audit
(CVE-2026-114952).
"""

from plugins.mysql.mysql_cve_2026_114952_audit import (
    MySQLAuditPlugin,
    parse_mysql_version,
    is_mysql_version_vulnerable,
)


def test_plugin_metadata():
    plugin = MySQLAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-114952"
    assert plugin.info["severity"] == "CRITICAL"
    assert "MySQL" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_mysql_version("8.4.12") == (8, 4, 12, False, "8.4.12")
    assert parse_mysql_version("9.7.3-commercial") == (9, 7, 3, False, "9.7.3-commercial")
    assert parse_mysql_version("8.0.40-ndb-8.0.40-cluster-gpl") == (
        8,
        0,
        40,
        True,
        "8.0.40-ndb-8.0.40-cluster-gpl",
    )
    assert parse_mysql_version("10.11.6-MariaDB-1:10.11.6+maria~ubu2204") is None


def test_version_vulnerability_logic():
    vuln_84, reason_84 = is_mysql_version_vulnerable(8, 4, 13, False, "8.4.13")
    assert vuln_84 is True
    assert "CVE-2026-114952" in reason_84

    safe_84, _ = is_mysql_version_vulnerable(8, 4, 14, False, "8.4.14")
    assert safe_84 is False

    vuln_97, _ = is_mysql_version_vulnerable(9, 7, 4, False, "9.7.4")
    assert vuln_97 is True

    safe_97, _ = is_mysql_version_vulnerable(9, 7, 5, False, "9.7.5")
    assert safe_97 is False

    vuln_2610, _ = is_mysql_version_vulnerable(26, 10, 0, False, "26.10")
    assert vuln_2610 is True

    vuln_ndb80, _ = is_mysql_version_vulnerable(8, 0, 50, True, "8.0.50-ndb-8.0.50")
    assert vuln_ndb80 is True

    safe_ndb80, _ = is_mysql_version_vulnerable(8, 0, 51, True, "8.0.51-ndb-8.0.51")
    assert safe_ndb80 is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = MySQLAuditPlugin()
    plugin.discovered_ports = [3306]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 3306,
            "service_detected": True,
            "version": "8.4.12",
            "source": "MySQL Initial Handshake Greeting",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-114952",
        },
    )
    res = plugin.run_audit("10.0.0.33", [3306])
    assert res["status"] == "Vulnerable"
    assert "8.4.12" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 3306,
            "service_detected": True,
            "version": "8.4.14",
            "source": "MySQL Initial Handshake Greeting",
            "is_vulnerable": False,
            "reason": "Patched >= 8.4.14",
        },
    )
    res_safe = plugin.run_audit("10.0.0.33", [3306])
    assert res_safe["status"] == "OK"
