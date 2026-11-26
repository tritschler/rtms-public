"""
test_jenkins_audit.py - Unit tests for Jenkins Script Security Plugin
Sandbox Bypass Audit (CVE-2026-136835).
"""

from plugins.jenkins.jenkins_cve_2026_136835_audit import (
    JenkinsScriptSecurityAuditPlugin,
    parse_jenkins_script_security_version,
    is_jenkins_script_security_vulnerable,
)


def test_plugin_metadata():
    plugin = JenkinsScriptSecurityAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-136835"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Jenkins Script Security" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    json_payload = '{"plugins":[{"shortName":"script-security","version":"1436.v1082791135e4"}]}'
    assert parse_jenkins_script_security_version(json_payload) == (
        1436,
        0,
        "1436.v1082791135e4",
    )

    xml_payload = "<plugin><shortName>script-security</shortName><version>1437.v9a8b7c6d5e4f</version></plugin>"
    assert parse_jenkins_script_security_version(xml_payload) == (
        1437,
        0,
        "1437.v9a8b7c6d5e4f",
    )

    banner = "Jenkins Script Security Plugin 1368.vb_b_402e3547e7"
    assert parse_jenkins_script_security_version(banner) == (
        1368,
        0,
        "1368.vb_b_402e3547e7",
    )
    assert parse_jenkins_script_security_version("nginx/1.26.0") is None


def test_version_vulnerability_logic():
    vuln, reason = is_jenkins_script_security_vulnerable(1436, 0, "1436.v1082791135e4")
    assert vuln is True
    assert "CVE-2026-136835" in reason

    vuln_older, _ = is_jenkins_script_security_vulnerable(1368, 0, "1368.vb_b_402e3547e7")
    assert vuln_older is True

    safe, _ = is_jenkins_script_security_vulnerable(1437, 0, "1437.v9a8b7c6d5e4f")
    assert safe is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = JenkinsScriptSecurityAuditPlugin()
    plugin.discovered_ports = [8080]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "version": "1436.v1082791135e4",
            "source": "Jenkins Plugin Manager REST API",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-136835",
        },
    )
    res = plugin.run_audit("10.0.0.60", [8080])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-136835" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "version": "1437.v9a8b7c6d5e4f",
            "source": "Jenkins Plugin Manager REST API",
            "is_vulnerable": False,
            "reason": "Patched > 1436.v1082791135e4",
        },
    )
    res_safe = plugin.run_audit("10.0.0.60", [8080])
    assert res_safe["status"] == "OK"
