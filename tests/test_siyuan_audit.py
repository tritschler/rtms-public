from plugins.siyuan.siyuan_cve_2026_137471_audit import (
    SiYuanAuditPlugin,
    is_siyuan_version_vulnerable,
    parse_siyuan_version,
)


def test_parse_siyuan_version():
    assert parse_siyuan_version("3.8.9") == (3, 8, 9)
    assert parse_siyuan_version("3.8.10") == (3, 8, 10)
    assert parse_siyuan_version("") is None


def test_is_siyuan_version_vulnerable():
    assert is_siyuan_version_vulnerable((3, 8, 9))[0] is True
    assert is_siyuan_version_vulnerable((3, 8, 10))[0] is False


def test_siyuan_run_audit():
    res_v = SiYuanAuditPlugin("siyuan.local", {"siyuan_version": "3.8.9"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-137471" in res_v["cve"]

    res_ok = SiYuanAuditPlugin("siyuan.local", {"siyuan_version": "3.8.10"}).run_audit()
    assert res_ok["status"] == "OK"
