"""
test_apache_ofbiz_audit.py - Unit tests for Apache OFBiz Audit Tool (CVE-2026-83542 / CVE-2026-82907).
"""

from plugins.apache_ofbiz.apache_ofbiz_cve_2026_83542_audit import (
    ApacheOfbizAuditPlugin,
    parse_ofbiz_version,
    is_ofbiz_vulnerable,
)


def test_plugin_metadata():
    plugin = ApacheOfbizAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-83542"
    assert plugin.info["severity"] == "CRITICAL"
    assert "Apache OFBiz" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"
    assert 8443 in plugin.target_ports
    assert 8080 in plugin.target_ports


def test_version_parsing():
    assert parse_ofbiz_version(
        "<footer>Powered by Apache OFBiz 24.09.05</footer>"
    ) == (24, 9, 5, "24.09.05")
    assert parse_ofbiz_version(
        "Apache OFBiz Release 24.09.07"
    ) == (24, 9, 7, "24.09.07")
    assert parse_ofbiz_version(
        "Apache-OFBiz/24.09.08"
    ) == (24, 9, 8, "24.09.08")
    assert parse_ofbiz_version("<html>Nginx</html>") is None
    assert parse_ofbiz_version("") is None


def test_version_vulnerability_logic():
    vuln, reason = is_ofbiz_vulnerable(24, 9, 5, "24.09.05")
    assert vuln is True
    assert "CVE-2026-83542" in reason

    vuln, _ = is_ofbiz_vulnerable(24, 9, 7, "24.09.07")
    assert vuln is True

    vuln, reason = is_ofbiz_vulnerable(24, 9, 8, "24.09.08")
    assert vuln is False
    assert "not affected" in reason

    vuln, _ = is_ofbiz_vulnerable(24, 9, 10, "24.09.10")
    assert vuln is False


def test_check_requirements():
    plugin = ApacheOfbizAuditPlugin()
    assert plugin.check_requirements("10.0.0.40", [8443, 8080]) is True
    assert 8443 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.40", {9443: {"name": "apache-ofbiz"}}) is True
    assert 9443 in plugin.discovered_ports
    assert plugin.check_requirements("10.0.0.40", [22, 25]) is False


def test_inspect_target_port_vulnerable(mocker):
    plugin = ApacheOfbizAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8443,
        "path": "/webtools/control/main",
        "status_code": 200,
        "headers": {"set-cookie": "OFBiz.Visitor=10000; Path=/"},
        "body_snippet": "<html><footer>Apache OFBiz Release 24.09.06</footer></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.40", 8443)
    assert hit is not None
    assert hit["ofbiz_detected"] is True
    assert hit["is_vulnerable"] is True
    assert hit["version"] == "24.09.06"


def test_inspect_target_port_patched(mocker):
    plugin = ApacheOfbizAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8443,
        "path": "/webtools/control/main",
        "status_code": 200,
        "headers": {"set-cookie": "OFBiz.Visitor=10000; Path=/"},
        "body_snippet": "<html><footer>Apache OFBiz Release 24.09.08</footer></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.41", 8443)
    assert hit is not None
    assert hit["ofbiz_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit["version"] == "24.09.08"


def test_inspect_target_port_concealed(mocker):
    plugin = ApacheOfbizAuditPlugin()
    mocker.patch.object(plugin, "probe_http_endpoint", return_value={
        "port": 8443,
        "path": "/webtools/control/main",
        "status_code": 200,
        "headers": {"set-cookie": "OFBiz.Visitor=10000; Path=/"},
        "body_snippet": "<html><title>Apache OFBiz Web Tools</title></html>"
    })

    hit = plugin.inspect_target_port("10.0.0.42", 8443)
    assert hit is not None
    assert hit["ofbiz_detected"] is True
    assert hit["is_vulnerable"] is False
    assert hit.get("concealed") is True


def test_run_audit_vulnerable_target(mocker):
    plugin = ApacheOfbizAuditPlugin()
    plugin.discovered_ports = [8443]
    mocker.patch.object(plugin, "inspect_target_port", return_value={
        "port": 8443,
        "ofbiz_detected": True,
        "version": "24.09.06",
        "source": "HTTP GET /webtools/control/main",
        "is_vulnerable": True,
        "reason": "Apache OFBiz 24.09.06 is affected by CVE-2026-83542."
    })

    res = plugin.run_audit("10.0.0.40", [8443])
    assert res["status"] == "Vulnerable"
    assert "CVE-2026-83542" in res["proof"]
    assert "24.09.06" in res["details"]
