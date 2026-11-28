from plugins.mendix_oidc.mendix_oidc_cve_2026_124981_audit import (
    MendixOIDCAuditPlugin,
    is_mendix_oidc_version_vulnerable,
    parse_mendix_oidc_version,
)


def test_parse_mendix_oidc_version():
    assert parse_mendix_oidc_version("5.4.0") == (10, 5, 4, 0)
    assert parse_mendix_oidc_version("mendix9:4.2.1") == (9, 4, 2, 1)
    assert parse_mendix_oidc_version("") is None


def test_is_mendix_oidc_version_vulnerable():
    assert is_mendix_oidc_version_vulnerable((10, 5, 9, 0))[0] is True
    assert is_mendix_oidc_version_vulnerable((10, 6, 0, 0))[0] is False
    assert is_mendix_oidc_version_vulnerable((9, 4, 2, 0))[0] is True
    assert is_mendix_oidc_version_vulnerable((9, 4, 3, 0))[0] is False


def test_mendix_oidc_run_audit():
    res_v = MendixOIDCAuditPlugin("mendix.local", {"oidc_version": "5.4.0"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-124981" in res_v["cve"]

    res_ok = MendixOIDCAuditPlugin("mendix.local", {"oidc_version": "6.0.0"}).run_audit()
    assert res_ok["status"] == "OK"
