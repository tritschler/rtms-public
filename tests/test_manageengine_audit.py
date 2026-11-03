"""
test_manageengine_audit.py - Unit tests for Zoho ManageEngine Log360 & EventLog Analyzer Audit Tool (CVE-2026-13594).
"""

from plugins.manageengine_log360.manageengine_cve_2026_13594_audit import (
    ManageEngineLog360AuditPlugin,
    parse_manageengine_build,
    is_manageengine_build_vulnerable,
)


def test_plugin_metadata():
    plugin = ManageEngineLog360AuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-13594"
    assert plugin.info["severity"] == "CRITICAL"
    assert "ManageEngine" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_build_parsing():
    assert parse_manageengine_build('{"BUILD_NUMBER":"13062","PRODUCT_NAME":"ManageEngine EventLog Analyzer"}') == 13062
    assert parse_manageengine_build('<script src="/event/js/app.js?build=13060"></script>') == 13060
    assert parse_manageengine_build('ManageEngine Log360 - Build 13063') == 13063
    assert parse_manageengine_build("<html>Nginx</html>") is None
    assert parse_manageengine_build("") is None


def test_build_vulnerability_logic():
    vuln, reason = is_manageengine_build_vulnerable(13062)
    assert vuln is True
    assert "CVE-2026-13594" in reason

    vuln, _ = is_manageengine_build_vulnerable(12500)
    assert vuln is True

    vuln, reason = is_manageengine_build_vulnerable(13063)
    assert vuln is False
    assert "patched" in reason


def test_check_requirements():
    plugin = ManageEngineLog360AuditPlugin()
    assert plugin.check_requirements("10.0.0.20", [8400, 8095]) is True
    assert 8400 in plugin.discovered_ports
    assert 8095 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.20", [22, 3306]) is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = ManageEngineLog360AuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8400,
        "path": "/event/index2.do",
        "status_code": 200,
        "headers": {"set-cookie": "EL_SESSIONID=xyz"},
        "body_snippet": "<html><title>ManageEngine EventLog Analyzer</title><script>var buildVersion = '13062';</script></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.60", 8400)
    assert hit is not None
    assert hit["manageengine_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["build"] == "13062"


def test_inspect_target_port_patched(mocker):
    plugin = ManageEngineLog360AuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8095,
        "path": "/apps/Home.do",
        "status_code": 200,
        "headers": {},
        "body_snippet": "<html><title>ManageEngine Log360</title><script>var buildVersion = '13065';</script></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.61", 8095)
    assert hit is not None
    assert hit["manageengine_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["build"] == "13065"


def test_run_audit_vulnerable_target(mocker):
    plugin = ManageEngineLog360AuditPlugin()
    plugin.discovered_ports = [8400]
    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 8400,
        "manageengine_detected": True,
        "product": "ManageEngine EventLog Analyzer",
        "build": "13060",
        "source": "HTTP GET /event/index2.do",
        "is_vulnerable": True,
        "reason": "ManageEngine build 13060 is vulnerable to CVE-2026-13594."
    })

    res = plugin.run_audit("10.0.0.60", [8400])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-13594" in res["proof"]
    assert "13060" in res["details"]
