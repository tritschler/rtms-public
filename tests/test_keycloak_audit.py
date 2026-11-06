"""
test_keycloak_audit.py - Unit tests for Keycloak SAML HTTP-Redirect Audit Tool (CVE-2026-117691).
"""

from plugins.keycloak.keycloak_cve_2026_117691_audit import (
    KeycloakAuditPlugin,
    parse_keycloak_version,
    is_keycloak_vulnerable,
)


def test_plugin_metadata():
    plugin = KeycloakAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-117691"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Keycloak" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"
    assert 8080 in plugin.target_ports
    assert 8443 in plugin.target_ports


def test_version_parsing():
    assert parse_keycloak_version(
        '<script src="/resources/26.1.2/admin/keycloak/index.js"></script>'
    ) == (26, 1, 2, "26.1.2")
    assert parse_keycloak_version(
        "Keycloak 25.0.6"
    ) == (25, 0, 6, "25.0.6")
    assert parse_keycloak_version(
        "/resources/26.2.0/common/keycloak/vendor.js"
    ) == (26, 2, 0, "26.2.0")
    assert parse_keycloak_version("<html>Apache</html>") is None
    assert parse_keycloak_version("") is None


def test_version_vulnerability_logic():
    vuln, reason = is_keycloak_vulnerable(26, 1, 2, "26.1.2")
    assert vuln is True
    assert "CVE-2026-117691" in reason

    vuln, _ = is_keycloak_vulnerable(24, 0, 5, "24.0.5")
    assert vuln is True

    vuln, reason = is_keycloak_vulnerable(26, 2, 0, "26.2.0")
    assert vuln is False
    assert "not affected" in reason

    vuln, _ = is_keycloak_vulnerable(26, 3, 1, "26.3.1")
    assert vuln is False


def test_check_requirements():
    plugin = KeycloakAuditPlugin()
    assert plugin.check_requirements("10.0.0.50", [8080, 8443]) is True
    assert 8080 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.50", {9080: {"name": "keycloak-sso"}}) is True
    assert 9080 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.50", [22, 25]) is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = KeycloakAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8080,
        "path": "/admin/master/console/",
        "status_code": 200,
        "headers": {"server": "Keycloak"},
        "body_snippet": '<link href="/resources/26.1.1/common/keycloak/patternfly.css" rel="stylesheet">'
    })

    hit = plugin.inspect_target_port("10.0.0.50", 8080)
    assert hit is not None
    assert hit["keycloak_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "26.1.1"


def test_inspect_target_port_patched(mocker):
    plugin = KeycloakAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8080,
        "path": "/admin/master/console/",
        "status_code": 200,
        "headers": {"server": "Keycloak"},
        "body_snippet": '<link href="/resources/26.2.0/common/keycloak/patternfly.css" rel="stylesheet">'
    })

    hit = plugin.inspect_target_port("10.0.0.51", 8080)
    assert hit is not None
    assert hit["keycloak_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["version"] == "26.2.0"


def test_inspect_target_port_concealed(mocker):
    plugin = KeycloakAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8080,
        "path": "/realms/master/.well-known/openid-configuration",
        "status_code": 200,
        "headers": {"content-type": "application/json"},
        "body_snippet": '{"issuer":"https://sso.example.com/realms/master","authorization_endpoint":"https://sso.example.com/realms/master/protocol/openid-connect/auth"}'
    })

    hit = plugin.inspect_target_port("10.0.0.52", 8080)
    assert hit is not None
    assert hit["keycloak_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit.get("concealed") is True


def test_run_audit_vulnerable_target(mocker):
    plugin = KeycloakAuditPlugin()
    plugin.discovered_ports = [8080]
    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 8080,
        "keycloak_detected": True,
        "version": "26.1.1",
        "source": "HTTP GET /admin/master/console/",
        "is_vulnerable": True,
        "reason": "Keycloak 26.1.1 is affected by CVE-2026-117691."
    })

    res = plugin.run_audit("10.0.0.50", [8080])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-117691" in res["proof"]
    assert "26.1.1" in res["details"]
