"""
test_manageengine_itsm_audit.py - Unit tests for Zoho ManageEngine ITSM & M365/DDI Suite Compliance Audit
(CVE-2026-12591, CVE-2026-12507, CVE-2026-19422).
"""

from plugins.manageengine_itsm.manageengine_itsm_cve_2026_12591_audit import (
    ManageEngineITSMAuditPlugin,
    parse_me_itsm_product_and_build,
    is_me_itsm_build_vulnerable,
)


def test_plugin_metadata():
    plugin = ManageEngineITSMAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-12591"
    assert plugin.info["severity"] == "CRITICAL"
    assert "ManageEngine" in plugin.info["name"]
    assert plugin.info["version"] == "1.0.0"


def test_product_and_build_parsing():
    assert parse_me_itsm_product_and_build(
        '<title>ManageEngine ServiceDesk Plus</title><script src="/js/app.js?build=15280"></script>'
    ) == ("ServiceDesk Plus", 15280)
    assert parse_me_itsm_product_and_build(
        '{"product": "ManageEngine M365 Manager Plus", "buildNumber": "4815"}'
    ) == ("M365 Manager Plus", 4815)
    assert parse_me_itsm_product_and_build(
        '<html>ManageEngine DDI Central - Build 6300</html>'
    ) == ("DDI Central", 6300)
    assert parse_me_itsm_product_and_build("<html>Apache Default Page</html>") is None


def test_build_vulnerability_logic():
    vuln_m365, reason_m365 = is_me_itsm_build_vulnerable("M365 Manager Plus", 4815)
    assert vuln_m365 is True
    assert "CVE-2026-12591" in reason_m365

    safe_m365, _ = is_me_itsm_build_vulnerable("M365 Manager Plus", 4818)
    assert safe_m365 is False

    vuln_sdp, reason_sdp = is_me_itsm_build_vulnerable("ServiceDesk Plus", 15285)
    assert vuln_sdp is True
    assert "CVE-2026-12507" in reason_sdp

    safe_sdp, _ = is_me_itsm_build_vulnerable("ServiceDesk Plus", 15290)
    assert safe_sdp is False

    vuln_ddi, reason_ddi = is_me_itsm_build_vulnerable("DDI Central", 6299)
    assert vuln_ddi is True
    assert "CVE-2026-19422" in reason_ddi

    safe_ddi, _ = is_me_itsm_build_vulnerable("DDI Central", 6301)
    assert safe_ddi is False


def test_run_audit_vulnerable_and_safe(mocker):
    plugin = ManageEngineITSMAuditPlugin()
    plugin.discovered_ports = [8080]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "product": "ServiceDesk Plus",
            "build": "15280",
            "source": "HTTP GET /",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-12507",
        },
    )
    res = plugin.run_audit("10.0.0.80", [8080])
    assert res["status"] == "Vulnerable"
    assert "15280" in res["proof"]

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8080,
            "service_detected": True,
            "product": "ServiceDesk Plus",
            "build": "15290",
            "source": "HTTP GET /",
            "is_vulnerable": False,
            "reason": "Patched >= 15290",
        },
    )
    res_safe = plugin.run_audit("10.0.0.80", [8080])
    assert res_safe["status"] == "OK"
