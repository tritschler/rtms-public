from plugins.parse_server.parse_server_cve_2026_137465_audit import (
    ParseServerAuditPlugin,
    is_parse_server_version_vulnerable,
    parse_parse_server_version,
)


def test_parse_parse_server_version():
    assert parse_parse_server_version("8.6.122") == (8, 6, 122, 9999)
    assert parse_parse_server_version("9.11.1-alpha.3") == (9, 11, 1, 3)
    assert parse_parse_server_version("") is None


def test_is_parse_server_version_vulnerable():
    assert is_parse_server_version_vulnerable((8, 6, 122, 9999))[0] is True
    assert is_parse_server_version_vulnerable((8, 6, 123, 9999))[0] is False
    assert is_parse_server_version_vulnerable((9, 11, 1, 3))[0] is True
    assert is_parse_server_version_vulnerable((9, 11, 1, 4))[0] is False


def test_parse_server_run_audit():
    res_v = ParseServerAuditPlugin("parse.local", {"parse_version": "8.6.122"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-137465" in res_v["cve"]

    res_ok = ParseServerAuditPlugin("parse.local", {"parse_version": "8.6.123"}).run_audit()
    assert res_ok["status"] == "OK"
