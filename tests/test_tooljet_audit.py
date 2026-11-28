from plugins.tooljet.tooljet_cve_2026_137536_audit import (
    ToolJetAuditPlugin,
    is_tooljet_version_vulnerable,
    parse_tooljet_version,
)


def test_parse_tooljet_version():
    assert parse_tooljet_version("3.21.93") == (3, 21, 93)
    assert parse_tooljet_version("3.21.96-LTS") == (3, 21, 96)
    assert parse_tooljet_version("") is None


def test_is_tooljet_version_vulnerable():
    assert is_tooljet_version_vulnerable((3, 21, 93))[0] is True
    assert is_tooljet_version_vulnerable((3, 21, 95))[0] is True
    assert is_tooljet_version_vulnerable((3, 21, 96))[0] is False


def test_tooljet_run_audit():
    res_v = ToolJetAuditPlugin("tooljet.local", {"tooljet_version": "3.21.93"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-137536" in res_v["cve"]
    assert "CVE-2026-137964" in res_v["cve"]

    res_ok = ToolJetAuditPlugin("tooljet.local", {"tooljet_version": "3.21.96-LTS"}).run_audit()
    assert res_ok["status"] == "OK"
