"""
test_pgadmin4_audit.py - Unit tests for pgAdmin 4 psql \\copy RCE & Lockout Bypass Audit Tool (CVE-2026-116241 / CVE-2026-116238).
"""

import pytest

from plugins.pgadmin4.pgadmin4_cve_2026_116241_audit import (
    PgAdmin4SecurityAuditPlugin,
    parse_pgadmin4_version,
    is_pgadmin4_version_vulnerable,
)


def test_plugin_metadata():
    plugin = PgAdmin4SecurityAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-116241"
    assert plugin.info["severity"] == "CRITICAL"
    assert "pgAdmin 4" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    # 1. pgAdmin 4 integer ?ver=MNNPP scheme
    assert parse_pgadmin4_version('<script src="/static/js/generated/app.bundle.js?ver=91800"></script>') == (9, 18, 0, "9.18")
    assert parse_pgadmin4_version('<link href="/static/css/style.css?ver=81402">') == (8, 14, 2, "8.14.2")
    assert parse_pgadmin4_version('<script src="/static/js/generated/app.bundle.js?ver=91900"></script>') == (9, 19, 0, "9.19")

    # 2. Dotted version strings
    assert parse_pgadmin4_version("pgAdmin 4 v9.17") == (9, 17, 0, "9.17")
    assert parse_pgadmin4_version('"app_version": "9.19.1"') == (9, 19, 1, "9.19.1")
    assert parse_pgadmin4_version("<html>Apache Server</html>") is None
    assert parse_pgadmin4_version("") is None


def test_version_vulnerability_logic():
    # Versions < 9.19 are vulnerable
    vuln, reason = is_pgadmin4_version_vulnerable(8, 14, 0)
    assert vuln is True
    assert "CVE-2026-116241" in reason
    assert "CVE-2026-116238" in reason

    vuln, _ = is_pgadmin4_version_vulnerable(9, 18, 0)
    assert vuln is True

    vuln, _ = is_pgadmin4_version_vulnerable(9, 18, 5)
    assert vuln is True

    # Versions >= 9.19 are patched
    vuln, reason = is_pgadmin4_version_vulnerable(9, 19, 0)
    assert vuln is False
    assert "patched" in reason

    vuln, _ = is_pgadmin4_version_vulnerable(9, 20, 0)
    assert vuln is False


def test_check_requirements():
    plugin = PgAdmin4SecurityAuditPlugin()

    # Ports as list
    assert plugin.check_requirements("10.0.0.30", [80, 5050]) is True
    assert 80 in plugin.discovered_ports
    assert 5050 in plugin.discovered_ports

    # Service dict
    services = {
        5050: {"name": "pgadmin"},
        8443: {"name": "https-alt"},
        22: {"name": "ssh"},
    }
    assert plugin.check_requirements("10.0.0.30", services) is True
    assert 5050 in plugin.discovered_ports
    assert 8443 in plugin.discovered_ports
    assert 22 not in plugin.discovered_ports

    # Non-web ports
    assert plugin.check_requirements("10.0.0.30", [22, 5432]) is False
    assert plugin.discovered_ports == []


def test_inspect_target_port_vulnerable(mocker):
    plugin = PgAdmin4SecurityAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 5050,
        "path": "/login",
        "status_code": 200,
        "headers": {"set-cookie": "pga4_session=abcd1234; Path=/; HttpOnly"},
        "body_snippet": '<html><head><title>pgAdmin 4</title><link href="/static/js/generated/style.css?ver=91800"></head></html>'
    })

    hit = plugin.inspect_target_port("192.168.1.40", 5050)
    assert hit is not None
    assert hit["pgadmin_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "9.18"


def test_inspect_target_port_patched(mocker):
    plugin = PgAdmin4SecurityAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 5050,
        "path": "/login",
        "status_code": 200,
        "headers": {"set-cookie": "pga4_session=abcd1234; Path=/; HttpOnly"},
        "body_snippet": '<html><head><title>pgAdmin 4</title><link href="/static/js/generated/style.css?ver=91900"></head></html>'
    })

    hit = plugin.inspect_target_port("192.168.1.41", 5050)
    assert hit is not None
    assert hit["pgadmin_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["version"] == "9.19"


def test_inspect_target_port_concealed(mocker):
    plugin = PgAdmin4SecurityAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "path": "/login",
        "status_code": 200,
        "headers": {"set-cookie": "pga4_session=abcd1234; Path=/; HttpOnly"},
        "body_snippet": "<html><head><title>pgAdmin 4</title></head><body>Login</body></html>"
    })

    hit = plugin.inspect_target_port("192.168.1.42", 443)
    assert hit is not None
    assert hit["pgadmin_detected"] is True
    assert hit["concealed"] is True
    assert hit["is_vulnerable"] is False


def test_run_audit_vulnerable_target(mocker):
    plugin = PgAdmin4SecurityAuditPlugin()
    plugin.discovered_ports = [5050]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 5050,
        "pgadmin_detected": True,
        "version": "9.18",
        "source": "HTTP GET /login (asset/page version metadata)",
        "is_vulnerable": True,
        "reason": "pgAdmin 4 9.18 is vulnerable to CVE-2026-116241 and CVE-2026-116238 (requires >= 9.19)."
    })

    res = plugin.run_audit("10.0.0.95", [5050])
    assert res["status"] == "Vulnerable"
    assert res["severity"] == "CRITICAL"
    assert "CVE-2026-116241" in res["proof"]
    assert "CVE-2026-116238" in res["proof"]
    assert "9.18" in res["details"]
    assert "9.19" in res["details"]


def test_run_audit_safe_target(mocker):
    plugin = PgAdmin4SecurityAuditPlugin()
    plugin.discovered_ports = [5050]

    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 5050,
        "pgadmin_detected": True,
        "version": "9.19",
        "source": "HTTP GET /login (asset/page version metadata)",
        "is_vulnerable": False,
        "reason": "pgAdmin 4 9.19 is patched against CVE-2026-116241 and CVE-2026-116238 (running >= 9.19)."
    })

    res = plugin.run_audit("10.0.0.96", [5050])
    assert res["status"] == "OK"
    assert "patched versions" in res["details"]
