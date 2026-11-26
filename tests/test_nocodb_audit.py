import pytest
from plugins.nocodb.nocodb_cve_2026_130730_audit import (
    NocoDBAuditPlugin,
    is_nocodb_version_vulnerable,
    parse_nocodb_version,
)


def test_parse_nocodb_version():
    assert parse_nocodb_version("2026.10.0") == (2026, 10, 0)
    assert parse_nocodb_version("2026.10.1") == (2026, 10, 1)
    assert parse_nocodb_version("") is None


def test_is_nocodb_version_vulnerable():
    assert is_nocodb_version_vulnerable((2026, 10, 0))[0] is True
    assert is_nocodb_version_vulnerable((0, 260, 0))[0] is True
    assert is_nocodb_version_vulnerable((2026, 10, 1))[0] is False


def test_nocodb_run_audit():
    p_v = NocoDBAuditPlugin("nocodb.local", {"nocodb_version": "2026.10.0"})
    res_v = p_v.run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-130730" in res_v["cve"]

    p_ok = NocoDBAuditPlugin("nocodb.local", {"nocodb_version": "2026.10.1"})
    assert p_ok.run_audit()["status"] == "OK"
