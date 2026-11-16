"""
test_cyrus_sasl_audit.py - Unit tests for Cyrus SASL SRP Authentication Bypass Audit
(CVE-2026-129483).
"""

from plugins.cyrus_sasl.cyrus_sasl_cve_2026_129483_audit import (
    CyrusSaslAuditPlugin,
    parse_cyrus_sasl_version,
    has_srp_mechanism_advertised,
    is_cyrus_sasl_version_vulnerable,
)


def test_plugin_metadata():
    plugin = CyrusSaslAuditPlugin()
    assert "CVE-2026-129483" in plugin.info["cve"]
    assert plugin.info["severity"] == "CRITICAL"
    assert "Cyrus SASL" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing_and_srp_detection():
    assert parse_cyrus_sasl_version("* OK [CAPABILITY IMAP4rev1 AUTH=SRP] Cyrus SASL 2.1.28 server ready") == (
        2,
        1,
        28,
        "2.1.28",
    )
    assert parse_cyrus_sasl_version("cyrus-sasl/2.1.29") == (2, 1, 29, "2.1.29")
    assert parse_cyrus_sasl_version("220 mail.example.com ESMTP Postfix") is None

    assert has_srp_mechanism_advertised("* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=SRP") is True
    assert has_srp_mechanism_advertised("250-AUTH PLAIN LOGIN SRP CRAM-MD5") is True
    assert has_srp_mechanism_advertised('"SASL" "PLAIN SRP"') is True
    assert has_srp_mechanism_advertised("250-AUTH PLAIN LOGIN") is False


def test_version_vulnerability_logic():
    vuln_2128, reason_2128 = is_cyrus_sasl_version_vulnerable(2, 1, 28)
    assert vuln_2128 is True
    assert "CVE-2026-129483" in reason_2128

    safe_2129, reason_2129 = is_cyrus_sasl_version_vulnerable(2, 1, 29)
    assert safe_2129 is False
    assert "patched" in reason_2129


def test_inspect_target_port_vulnerable_and_warning(mocker):
    plugin = CyrusSaslAuditPlugin()
    mocker.patch.object(
        plugin,
        "probe_sasl_endpoint",
        return_value={
            "port": 143,
            "banner": "* OK Cyrus IMAP (Cyrus SASL 2.1.28) ready",
            "capabilities": "* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=SRP",
            "combined": "* OK Cyrus IMAP (Cyrus SASL 2.1.28) ready\n* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=SRP",
        },
    )

    hit = plugin.inspect_target_port("10.0.0.40", 143)
    assert hit is not None
    assert hit["service_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "2.1.28"
    assert hit["srp_advertised"] is True

    mocker.patch.object(
        plugin,
        "probe_sasl_endpoint",
        return_value={
            "port": 25,
            "banner": "220 mail.example.com ESMTP Postfix",
            "capabilities": "250-AUTH PLAIN LOGIN SRP",
            "combined": "220 mail.example.com ESMTP Postfix\n250-AUTH PLAIN LOGIN SRP",
        },
    )
    hit_concealed = plugin.inspect_target_port("10.0.0.40", 25)
    assert hit_concealed is not None
    assert hit_concealed["concealed"] is True
    assert hit_concealed["is_vulnerable"] is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = CyrusSaslAuditPlugin()
    plugin.discovered_ports = [143]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 143,
            "service_detected": True,
            "version": "2.1.28",
            "source": "Service Banner / Capabilities (Port 143)",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-129483 (<= 2.1.28)",
        },
    )
    res = plugin.run_audit("10.0.0.40", [143])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-129483" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 143,
            "service_detected": True,
            "version": "2.1.29",
            "source": "Service Banner / Capabilities (Port 143)",
            "is_vulnerable": False,
            "reason": "Patched >= 2.1.29",
        },
    )
    res_safe = plugin.run_audit("10.0.0.40", [143])
    assert res_safe["status"] == "OK"
