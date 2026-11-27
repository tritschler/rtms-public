from plugins.eclipse_ditto.eclipse_ditto_cve_2026_135203_audit import (
    EclipseDittoAuditPlugin,
    is_eclipse_ditto_version_vulnerable,
    parse_eclipse_ditto_version,
)


def test_parse_eclipse_ditto_version():
    assert parse_eclipse_ditto_version("3.8.15") == (3, 8, 15)
    assert parse_eclipse_ditto_version("3.9.9") == (3, 9, 9)
    assert parse_eclipse_ditto_version("") is None


def test_is_eclipse_ditto_version_vulnerable():
    assert is_eclipse_ditto_version_vulnerable((3, 8, 15))[0] is True
    assert is_eclipse_ditto_version_vulnerable((3, 8, 16))[0] is False
    assert is_eclipse_ditto_version_vulnerable((3, 9, 9))[0] is True
    assert is_eclipse_ditto_version_vulnerable((3, 9, 10))[0] is False


def test_eclipse_ditto_run_audit():
    res_v = EclipseDittoAuditPlugin("ditto.local", {"ditto_version": "3.9.9"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-135203" in res_v["cve"]

    res_ok = EclipseDittoAuditPlugin("ditto.local", {"ditto_version": "3.9.10"}).run_audit()
    assert res_ok["status"] == "OK"
