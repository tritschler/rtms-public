from plugins.coder.coder_cve_2026_137547_audit import (
    CoderAuditPlugin,
    is_coder_version_vulnerable,
    parse_coder_version,
)


def test_parse_coder_version():
    assert parse_coder_version("v2.38.6") == (2, 38, 6)
    assert parse_coder_version("2.39.1") == (2, 39, 1)
    assert parse_coder_version("") is None


def test_is_coder_version_vulnerable():
    assert is_coder_version_vulnerable((2, 29, 26))[0] is True
    assert is_coder_version_vulnerable((2, 29, 27))[0] is False
    assert is_coder_version_vulnerable((2, 34, 18))[0] is True
    assert is_coder_version_vulnerable((2, 34, 19))[0] is False
    assert is_coder_version_vulnerable((2, 37, 10))[0] is True
    assert is_coder_version_vulnerable((2, 37, 11))[0] is False
    assert is_coder_version_vulnerable((2, 38, 6))[0] is True
    assert is_coder_version_vulnerable((2, 38, 7))[0] is False
    assert is_coder_version_vulnerable((2, 39, 0))[0] is True
    assert is_coder_version_vulnerable((2, 39, 1))[0] is False


def test_coder_run_audit():
    res_v = CoderAuditPlugin("coder.local", {"coder_version": "2.39.0"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-137547" in res_v["cve"]

    res_ok = CoderAuditPlugin("coder.local", {"coder_version": "2.39.1"}).run_audit()
    assert res_ok["status"] == "OK"
