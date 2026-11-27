from plugins.budibase.budibase_cve_2026_137498_audit import (
    BudibaseAuditPlugin,
    is_budibase_version_vulnerable,
    parse_budibase_version,
)


def test_parse_budibase_version():
    assert parse_budibase_version("3.41.0") == (3, 41, 0)
    assert parse_budibase_version("4.0.0") == (4, 0, 0)
    assert parse_budibase_version("") is None


def test_is_budibase_version_vulnerable():
    assert is_budibase_version_vulnerable((3, 39, 18))[0] is True
    assert is_budibase_version_vulnerable((3, 41, 2))[0] is True
    assert is_budibase_version_vulnerable((4, 0, 0))[0] is False


def test_budibase_run_audit():
    res_v = BudibaseAuditPlugin("budibase.local", {"budibase_version": "3.41.0"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-137498" in res_v["cve"]
    assert "CVE-2026-137499" in res_v["cve"]

    res_ok = BudibaseAuditPlugin("budibase.local", {"budibase_version": "4.0.0"}).run_audit()
    assert res_ok["status"] == "OK"
