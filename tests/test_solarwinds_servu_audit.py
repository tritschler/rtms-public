import pytest
from plugins.solarwinds_servu.solarwinds_servu_cve_2026_123172_audit import (
    SolarWindsServUAuditPlugin,
    is_servu_version_vulnerable,
    parse_servu_version,
)


def test_parse_servu_version():
    assert parse_servu_version("2026.3") == (2026, 3, 0)
    assert parse_servu_version("15.5.3") == (15, 5, 3)
    assert parse_servu_version("") is None


def test_is_servu_version_vulnerable():
    assert is_servu_version_vulnerable((2026, 3, 0))[0] is True
    assert is_servu_version_vulnerable((15, 5, 3))[0] is True
    assert is_servu_version_vulnerable((2026, 4, 0))[0] is False


def test_servu_run_audit():
    p_v = SolarWindsServUAuditPlugin("servu.local", {"servu_version": "2026.3"})
    res_v = p_v.run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-123172" in res_v["cve"]
    assert len(res_v["cve"]) == 9

    p_ok = SolarWindsServUAuditPlugin("servu.local", {"servu_version": "2026.4"})
    assert p_ok.run_audit()["status"] == "OK"
