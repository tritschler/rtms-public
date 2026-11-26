import pytest
from plugins.webmin.webmin_cve_2026_134639_audit import (
    WebminAuditPlugin,
    is_webmin_version_vulnerable,
    parse_webmin_version,
)


def test_parse_webmin_version():
    assert parse_webmin_version("2.670") == (2, 670, 0)
    assert parse_webmin_version("MiniServ/2.671") == (2, 671, 0)
    assert parse_webmin_version("") is None


def test_is_webmin_version_vulnerable():
    assert is_webmin_version_vulnerable((2, 670, 0))[0] is True
    assert is_webmin_version_vulnerable((2, 671, 0))[0] is False


def test_webmin_run_audit():
    p_v = WebminAuditPlugin("webmin.local", {"webmin_version": "2.670"})
    res_v = p_v.run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-134639" in res_v["cve"]

    p_ok = WebminAuditPlugin("webmin.local", {"webmin_version": "2.671"})
    assert p_ok.run_audit()["status"] == "OK"
