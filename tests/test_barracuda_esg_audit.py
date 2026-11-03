"""
test_barracuda_esg_audit.py - Unit tests for Barracuda Email Security Gateway Audit Tool (CVE-2026-116606).
"""

from plugins.barracuda_esg.barracuda_esg_cve_2026_116606_audit import (
    BarracudaEsgAuditPlugin,
    parse_barracuda_esg_version,
    is_barracuda_esg_vulnerable,
)


def test_plugin_metadata():
    plugin = BarracudaEsgAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-116606"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Barracuda" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_version_parsing():
    assert parse_barracuda_esg_version('<link rel="stylesheet" href="/barracuda.css?v=9.4.0.025">') == (9, 4, 0, 25, "9.4.0.025")
    assert parse_barracuda_esg_version('Barracuda Email Security Gateway Firmware v9.4.0.030') == (9, 4, 0, 30, "9.4.0.030")
    assert parse_barracuda_esg_version("<html>Postfix</html>") is None
    assert parse_barracuda_esg_version("") is None


def test_version_vulnerability_logic():
    vuln, reason = is_barracuda_esg_vulnerable(9, 4, 0, 29, "9.4.0.029")
    assert vuln is True
    assert "CVE-2026-116606" in reason

    vuln, _ = is_barracuda_esg_vulnerable(9, 3, 1, 4, "9.3.1.004")
    assert vuln is True

    vuln, reason = is_barracuda_esg_vulnerable(9, 4, 0, 30, "9.4.0.030")
    assert vuln is False
    assert "patched" in reason


def test_check_requirements():
    plugin = BarracudaEsgAuditPlugin()
    assert plugin.check_requirements("10.0.0.30", [443, 8000]) is True
    assert 8000 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.30", [22, 25]) is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = BarracudaEsgAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8000,
        "path": "/cgi-mod/index.cgi",
        "status_code": 200,
        "headers": {"set-cookie": "barra_counter_session=12345"},
        "body_snippet": '<html><title>Barracuda Email Security Gateway</title><link href="/barracuda.css?v=9.4.0.025"></html>'
    })

    hit = plugin.inspect_target_port("10.0.0.70", 8000)
    assert hit is not None
    assert hit["barracuda_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "9.4.0.025"


def test_inspect_target_port_patched(mocker):
    plugin = BarracudaEsgAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 443,
        "path": "/cgi-mod/index.cgi",
        "status_code": 200,
        "headers": {"set-cookie": "barra_counter_session=12345"},
        "body_snippet": '<html><title>Barracuda Email Security Gateway</title><link href="/barracuda.css?v=9.4.0.030"></html>'
    })

    hit = plugin.inspect_target_port("10.0.0.71", 443)
    assert hit is not None
    assert hit["barracuda_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["version"] == "9.4.0.030"


def test_run_audit_vulnerable_target(mocker):
    plugin = BarracudaEsgAuditPlugin()
    plugin.discovered_ports = [8000]
    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 8000,
        "barracuda_detected": True,
        "version": "9.4.0.025",
        "source": "HTTP GET /cgi-mod/index.cgi",
        "is_vulnerable": True,
        "reason": "Barracuda ESG firmware 9.4.0.025 is vulnerable to CVE-2026-116606."
    })

    res = plugin.run_audit("10.0.0.70", [8000])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-116606" in res["proof"]
    assert "9.4.0.025" in res["details"]
