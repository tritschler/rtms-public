"""
test_vsftpd_audit.py - Unit tests for vsftpd FTPS Data Channel Hijacking Audit Tool (CVE-2026-119568).
"""

import pytest

from plugins.vsftpd.vsftpd_cve_2026_119568_audit import (
    VsftpdFTPSHijackAuditPlugin,
    parse_vsftpd_version,
    is_vsftpd_version_vulnerable,
)


def test_plugin_metadata():
    plugin = VsftpdFTPSHijackAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-119568"
    assert plugin.info["severity"] == "CRITICAL"
    assert "vsftpd" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_vsftpd_version("220 (vsFTPd 3.0.5)") == (3, 0, 5, "3.0.5")
    assert parse_vsftpd_version("220-Welcome to vsftpd 3.0.3-ubuntu1") == (3, 0, 3, "3.0.3")
    assert parse_vsftpd_version("220 (vsFTPd 2.3.4)") == (2, 3, 4, "2.3.4")
    assert parse_vsftpd_version("220 (vsFTPd 3.0.6)") == (3, 0, 6, "3.0.6")
    assert parse_vsftpd_version("220 ProFTPD Server ready.") is None
    assert parse_vsftpd_version("") is None


def test_version_vulnerability_logic():
    # Versions <= 3.0.5 are vulnerable
    vuln, reason = is_vsftpd_version_vulnerable(2, 3, 4)
    assert vuln is True
    assert "CVE-2026-119568" in reason

    vuln, _ = is_vsftpd_version_vulnerable(3, 0, 3)
    assert vuln is True

    vuln, _ = is_vsftpd_version_vulnerable(3, 0, 5)
    assert vuln is True

    # Versions >= 3.0.6 are patched
    vuln, reason = is_vsftpd_version_vulnerable(3, 0, 6)
    assert vuln is False
    assert "patched" in reason

    vuln, _ = is_vsftpd_version_vulnerable(3, 1, 0)
    assert vuln is False


def test_check_requirements():
    plugin = VsftpdFTPSHijackAuditPlugin()

    # Ports as list
    assert plugin.check_requirements("10.0.0.20", [21, 990]) is True
    assert 21 in plugin.discovered_ports
    assert 990 in plugin.discovered_ports

    # Service dict
    services = {
        2121: {"name": "ftp-alt"},
        990: {"name": "ftps"},
        80: {"name": "http"},
    }
    assert plugin.check_requirements("10.0.0.20", services) is True
    assert 2121 in plugin.discovered_ports
    assert 990 in plugin.discovered_ports
    assert 80 not in plugin.discovered_ports

    # Non-FTP ports only
    assert plugin.check_requirements("10.0.0.20", [22, 80, 443]) is False
    assert plugin.discovered_ports == []


def test_inspect_target_port_vulnerable_ftps(mocker):
    plugin = VsftpdFTPSHijackAuditPlugin()
    mocker.patch.object(plugin, "probe_ftp_endpoint", return_value={
        "port": 21,
        "banner": "220 (vsFTPd 3.0.5)",
        "auth_tls_supported": True,
        "auth_tls_response": "234 Proceed with negotiation."
    })

    hit = plugin.inspect_target_port("192.168.1.30", 21)
    assert hit is not None
    assert hit["ftp_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "3.0.5"
    assert "ssl_data_accept()" in hit["reason"]


def test_inspect_target_port_mitigated_no_tls(mocker):
    plugin = VsftpdFTPSHijackAuditPlugin()
    mocker.patch.object(plugin, "probe_ftp_endpoint", return_value={
        "port": 21,
        "banner": "220 (vsFTPd 3.0.5)",
        "auth_tls_supported": False,
        "auth_tls_response": "530 This FTP server is anonymous only."
    })

    hit = plugin.inspect_target_port("192.168.1.31", 21)
    assert hit is not None
    assert hit["ftp_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["mitigated"] is True


def test_inspect_target_port_patched(mocker):
    plugin = VsftpdFTPSHijackAuditPlugin()
    mocker.patch.object(plugin, "probe_ftp_endpoint", return_value={
        "port": 21,
        "banner": "220 (vsFTPd 3.0.6)",
        "auth_tls_supported": True,
        "auth_tls_response": "234 Proceed with negotiation."
    })

    hit = plugin.inspect_target_port("192.168.1.32", 21)
    assert hit is not None
    assert hit["ftp_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["version"] == "3.0.6"


def test_inspect_target_port_concealed_banner(mocker):
    plugin = VsftpdFTPSHijackAuditPlugin()
    mocker.patch.object(plugin, "probe_ftp_endpoint", return_value={
        "port": 21,
        "banner": "220 Corporate FTP Server Ready.",
        "auth_tls_supported": True,
        "auth_tls_response": "234 Proceed with negotiation."
    })

    hit = plugin.inspect_target_port("192.168.1.33", 21)
    assert hit is not None
    assert hit["ftp_detected"] is True
    assert hit["concealed"] is True
    assert hit["is_vulnerable"] is False


def test_run_audit_vulnerable_target(mocker):
    plugin = VsftpdFTPSHijackAuditPlugin()
    plugin.discovered_ports = [21]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 21,
        "ftp_detected": True,
        "vsftpd_detected": True,
        "version": "3.0.5",
        "banner": "220 (vsFTPd 3.0.5)",
        "auth_tls_supported": True,
        "auth_tls_response": "234 Proceed with negotiation.",
        "is_vulnerable": True,
        "reason": "vsftpd 3.0.5 is vulnerable to CVE-2026-119568 (affected: <= 3.0.5; requires >= 3.0.6)."
    })

    res = plugin.run_audit("10.0.0.90", [21])
    assert res["status"] == "Vulnerable"
    assert res["severity"] == "CRITICAL"
    assert "CVE-2026-119568" in res["proof"]
    assert "3.0.5" in res["details"]
    assert "require_ssl_reuse=YES" in res["details"]


def test_run_audit_safe_target(mocker):
    plugin = VsftpdFTPSHijackAuditPlugin()
    plugin.discovered_ports = [21]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 21,
        "ftp_detected": True,
        "vsftpd_detected": True,
        "version": "3.0.6",
        "banner": "220 (vsFTPd 3.0.6)",
        "auth_tls_supported": True,
        "auth_tls_response": "234 Proceed with negotiation.",
        "is_vulnerable": False,
        "reason": "vsftpd 3.0.6 is patched against CVE-2026-119568 (running >= 3.0.6)."
    })

    res = plugin.run_audit("10.0.0.91", [21])
    assert res["status"] == "OK"
    assert "patched versions" in res["details"]
