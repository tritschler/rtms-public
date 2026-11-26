import pytest
from plugins.camunda.camunda_cve_2026_77230_audit import (
    CamundaAuditPlugin,
    is_camunda_version_vulnerable,
    parse_camunda_version,
)


def test_parse_camunda_version():
    assert parse_camunda_version("8.10.9") == (8, 10, 9, 9999)
    assert parse_camunda_version("8.11.0-alpha1") == (8, 11, 0, 1)
    assert parse_camunda_version("") is None


def test_is_camunda_version_vulnerable():
    assert is_camunda_version_vulnerable((8, 8, 46, 9999)) == (True, "8.8.47")
    assert is_camunda_version_vulnerable((8, 9, 28, 9999)) == (True, "8.9.29")
    assert is_camunda_version_vulnerable((8, 10, 9, 9999)) == (True, "8.10.10")
    assert is_camunda_version_vulnerable((8, 11, 0, 1)) == (True, "8.11.0")
    assert is_camunda_version_vulnerable((8, 10, 10, 9999))[0] is False


def test_camunda_run_audit():
    p_v = CamundaAuditPlugin("camunda.local", {"camunda_version": "8.10.9"})
    res_v = p_v.run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-77230" in res_v["cve"]

    p_ok = CamundaAuditPlugin("camunda.local", {"camunda_version": "8.10.10"})
    assert p_ok.run_audit()["status"] == "OK"
