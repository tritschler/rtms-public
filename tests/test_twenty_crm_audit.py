from plugins.twenty_crm.twenty_crm_cve_2026_137584_audit import (
    TwentyCRMAuditPlugin,
    is_twenty_version_vulnerable,
    parse_twenty_version,
)


def test_parse_twenty_version():
    assert parse_twenty_version("2.63.0") == (2, 63, 0)
    assert parse_twenty_version("2.63.1") == (2, 63, 1)
    assert parse_twenty_version("") is None


def test_is_twenty_version_vulnerable():
    assert is_twenty_version_vulnerable((2, 63, 0))[0] is True
    assert is_twenty_version_vulnerable((2, 63, 1))[0] is False


def test_twenty_crm_run_audit():
    res_v = TwentyCRMAuditPlugin("twenty.local", {"twenty_version": "2.63.0"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-137584" in res_v["cve"]

    res_ok = TwentyCRMAuditPlugin("twenty.local", {"twenty_version": "2.63.1"}).run_audit()
    assert res_ok["status"] == "OK"
