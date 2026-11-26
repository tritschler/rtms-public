import pytest
from plugins.fortianalyzer.fortianalyzer_cve_2026_126229_audit import (
    FortiAnalyzerAuditPlugin,
    is_fortianalyzer_version_vulnerable,
    parse_fortianalyzer_version,
)


def test_parse_fortianalyzer_version():
    assert parse_fortianalyzer_version("v7.6.7") == (7, 6, 7)
    assert parse_fortianalyzer_version("8.0.2") == (8, 0, 2)
    assert parse_fortianalyzer_version("") is None


def test_is_fortianalyzer_version_vulnerable():
    assert is_fortianalyzer_version_vulnerable((7, 2, 12)) == (True, "7.2.13")
    assert is_fortianalyzer_version_vulnerable((7, 4, 11)) == (True, "7.4.12")
    assert is_fortianalyzer_version_vulnerable((7, 6, 7)) == (True, "7.6.8")
    assert is_fortianalyzer_version_vulnerable((8, 0, 1)) == (True, "8.0.2")
    assert is_fortianalyzer_version_vulnerable((8, 0, 2))[0] is False


def test_fortianalyzer_run_audit():
    p_v = FortiAnalyzerAuditPlugin("faz.local", {"fortianalyzer_version": "7.6.7"})
    res_v = p_v.run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-126229" in res_v["cve"]

    p_ok = FortiAnalyzerAuditPlugin("faz.local", {"fortianalyzer_version": "7.6.8"})
    assert p_ok.run_audit()["status"] == "OK"
