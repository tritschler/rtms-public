"""
test_freeswitch_audit.py - Unit tests for FreeSWITCH Audit Tool (CVE-2026-116779).
"""

from plugins.freeswitch.freeswitch_cve_2026_116779_audit import (
    FreeSwitchAuditPlugin,
    parse_freeswitch_version,
    is_freeswitch_vulnerable,
)


def test_plugin_metadata():
    plugin = FreeSwitchAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-116779"
    assert plugin.info["severity"] == "CRITICAL"
    assert "FreeSWITCH" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"
    assert 5060 in plugin.target_ports
    assert 5061 in plugin.target_ports


def test_version_parsing():
    assert parse_freeswitch_version(
        "FreeSWITCH-mod_sofia/1.10.12-release~64bit"
    ) == (1, 10, 12, "1.10.12")
    assert parse_freeswitch_version(
        "FreeSWITCH/1.11.2"
    ) == (1, 11, 2, "1.11.2")
    assert parse_freeswitch_version(
        "FreeSWITCH Version 1.11.3"
    ) == (1, 11, 3, "1.11.3")
    assert parse_freeswitch_version("Asterisk PBX 20.1") is None
    assert parse_freeswitch_version("") is None


def test_version_vulnerability_logic():
    vuln, reason = is_freeswitch_vulnerable(1, 10, 12, "1.10.12")
    assert vuln is True
    assert "CVE-2026-116779" in reason

    vuln, _ = is_freeswitch_vulnerable(1, 11, 2, "1.11.2")
    assert vuln is True

    vuln, reason = is_freeswitch_vulnerable(1, 11, 3, "1.11.3")
    assert vuln is False
    assert "not affected" in reason

    vuln, _ = is_freeswitch_vulnerable(1, 12, 0, "1.12.0")
    assert vuln is False


def test_check_requirements():
    plugin = FreeSwitchAuditPlugin()
    assert plugin.check_requirements("10.0.0.60", [5060, 5080]) is True
    assert 5060 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.60", {6060: {"name": "sip-freeswitch"}}) is True
    assert 6060 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.60", [22, 25]) is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = FreeSwitchAuditPlugin()
    mocker.patch.object(plugin, "probe_sip_options", return_value={
        "port": 5060,
        "protocol": "SIP/TCP",
        "raw_response": "SIP/2.0 200 OK\r\nUser-Agent: FreeSWITCH-mod_sofia/1.11.1-release\r\n\r\n",
        "headers": {"user-agent": "FreeSWITCH-mod_sofia/1.11.1-release"}
    })

    hit = plugin.inspect_target_port("10.0.0.60", 5060)
    assert hit is not None
    assert hit["freeswitch_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "1.11.1"


def test_inspect_target_port_patched(mocker):
    plugin = FreeSwitchAuditPlugin()
    mocker.patch.object(plugin, "probe_sip_options", return_value={
        "port": 5060,
        "protocol": "SIP/TCP",
        "raw_response": "SIP/2.0 200 OK\r\nUser-Agent: FreeSWITCH-mod_sofia/1.11.3-release\r\n\r\n",
        "headers": {"user-agent": "FreeSWITCH-mod_sofia/1.11.3-release"}
    })

    hit = plugin.inspect_target_port("10.0.0.61", 5060)
    assert hit is not None
    assert hit["freeswitch_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["version"] == "1.11.3"


def test_inspect_target_port_concealed(mocker):
    plugin = FreeSwitchAuditPlugin()
    mocker.patch.object(plugin, "probe_sip_options", return_value={
        "port": 5060,
        "protocol": "SIP/TCP",
        "raw_response": "SIP/2.0 200 OK\r\nUser-Agent: FreeSWITCH\r\n\r\n",
        "headers": {"user-agent": "FreeSWITCH"}
    })

    hit = plugin.inspect_target_port("10.0.0.62", 5060)
    assert hit is not None
    assert hit["freeswitch_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit.get("concealed") is True


def test_run_audit_vulnerable_target(mocker):
    plugin = FreeSwitchAuditPlugin()
    plugin.discovered_ports = [5060]
    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 5060,
        "freeswitch_detected": True,
        "version": "1.11.1",
        "source": "SIP/TCP OPTIONS",
        "is_vulnerable": True,
        "reason": "FreeSWITCH 1.11.1 is affected by CVE-2026-116779."
    })

    res = plugin.run_audit("10.0.0.60", [5060])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-116779" in res["proof"]
    assert "1.11.1" in res["details"]
