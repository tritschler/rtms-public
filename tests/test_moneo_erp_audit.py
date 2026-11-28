from plugins.moneo_erp.moneo_erp_cve_2026_59103_audit import (
    MoneoERPAuditPlugin,
    is_moneo_version_vulnerable,
    parse_moneo_version,
)


def test_parse_moneo_version():
    assert parse_moneo_version("2026.11.20") == (2026, 11, 20)
    assert parse_moneo_version("2026-11-28") == (2026, 11, 28)
    assert parse_moneo_version("") is None


def test_is_moneo_version_vulnerable():
    assert is_moneo_version_vulnerable((2026, 11, 20))[0] is True
    assert is_moneo_version_vulnerable((2026, 11, 28))[0] is False


def test_moneo_erp_run_audit():
    res_v = MoneoERPAuditPlugin("moneo.local", {"moneo_version": "2026.11.20"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-59103" in res_v["cve"]

    res_ok = MoneoERPAuditPlugin("moneo.local", {"moneo_version": "2026.11.28"}).run_audit()
    assert res_ok["status"] == "OK"
