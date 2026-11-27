from plugins.seppmail.seppmail_cve_2026_130637_audit import (
    SEPPmailAuditPlugin,
    is_seppmail_version_vulnerable,
    parse_seppmail_version,
)


def test_parse_seppmail_version():
    assert parse_seppmail_version("15.1.1") == (15, 1, 1)
    assert parse_seppmail_version("15.1.2") == (15, 1, 2)
    assert parse_seppmail_version("") is None


def test_is_seppmail_version_vulnerable():
    assert is_seppmail_version_vulnerable((15, 1, 1))[0] is True
    assert is_seppmail_version_vulnerable((15, 1, 2))[0] is False


def test_seppmail_run_audit():
    res_v = SEPPmailAuditPlugin("seppmail.local", {"seppmail_version": "15.1.1"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-130637" in res_v["cve"]
    assert "CVE-2026-124843" in res_v["cve"]
    assert "CVE-2026-124840" in res_v["cve"]

    res_ok = SEPPmailAuditPlugin("seppmail.local", {"seppmail_version": "15.1.2"}).run_audit()
    assert res_ok["status"] == "OK"
