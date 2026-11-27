from plugins.canonical_lxd.canonical_lxd_cve_2026_135384_audit import (
    CanonicalLXDAuditPlugin,
    is_lxd_version_vulnerable,
    parse_lxd_version,
)


def test_parse_lxd_version():
    assert parse_lxd_version("5.21.9") == ("lxd", 5, 21, 9)
    assert parse_lxd_version("pylxd 2.4.2") == ("pylxd", 2, 4, 2)
    assert parse_lxd_version("") is None


def test_is_lxd_version_vulnerable():
    assert is_lxd_version_vulnerable(("lxd", 5, 0, 11))[0] is True
    assert is_lxd_version_vulnerable(("lxd", 5, 0, 12))[0] is False
    assert is_lxd_version_vulnerable(("lxd", 5, 21, 9))[0] is True
    assert is_lxd_version_vulnerable(("lxd", 5, 21, 10))[0] is False
    assert is_lxd_version_vulnerable(("lxd", 6, 10, 1))[0] is True
    assert is_lxd_version_vulnerable(("lxd", 6, 10, 2))[0] is False
    assert is_lxd_version_vulnerable(("pylxd", 2, 4, 2))[0] is True
    assert is_lxd_version_vulnerable(("pylxd", 2, 4, 3))[0] is False


def test_canonical_lxd_run_audit():
    res_v = CanonicalLXDAuditPlugin("lxd.local", {"lxd_version": "6.10.1"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-135384" in res_v["cve"]
    assert "CVE-2026-127163" in res_v["cve"]

    res_ok = CanonicalLXDAuditPlugin("lxd.local", {"lxd_version": "6.10.2"}).run_audit()
    assert res_ok["status"] == "OK"
