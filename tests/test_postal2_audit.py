from plugins.postal2.postal2_cve_2026_138154_audit import (
    Postal2AuditPlugin,
    is_postal2_build_vulnerable,
    parse_postal2_build,
)


def test_parse_postal2_build():
    assert parse_postal2_build("build 26810490") == 26810490
    assert parse_postal2_build("26810491") == 26810491
    assert parse_postal2_build("") is None


def test_is_postal2_build_vulnerable():
    assert is_postal2_build_vulnerable(26810490)[0] is True
    assert is_postal2_build_vulnerable(26810491)[0] is False


def test_postal2_run_audit():
    res_v = Postal2AuditPlugin("host.local", {"build_version": "26810490"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-138154" in res_v["cve"]

    res_ok = Postal2AuditPlugin("host.local", {"build_version": "26810491"}).run_audit()
    assert res_ok["status"] == "OK"
