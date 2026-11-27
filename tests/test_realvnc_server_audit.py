from plugins.realvnc_server.realvnc_server_cve_2026_137738_audit import (
    RealVNCServerAuditPlugin,
    is_realvnc_version_vulnerable,
    parse_realvnc_version,
)


def test_parse_realvnc_version():
    assert parse_realvnc_version("7.19.0") == (7, 19, 0)
    assert parse_realvnc_version("7.19.1") == (7, 19, 1)
    assert parse_realvnc_version("") is None


def test_is_realvnc_version_vulnerable():
    assert is_realvnc_version_vulnerable((7, 19, 0))[0] is True
    assert is_realvnc_version_vulnerable((7, 19, 1))[0] is False


def test_realvnc_run_audit():
    res_v = RealVNCServerAuditPlugin("vnc.local", {"realvnc_version": "7.19.0"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-137738" in res_v["cve"]

    res_ok = RealVNCServerAuditPlugin("vnc.local", {"realvnc_version": "7.19.1"}).run_audit()
    assert res_ok["status"] == "OK"
