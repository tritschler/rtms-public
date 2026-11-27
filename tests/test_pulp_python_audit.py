from plugins.pulp_python.pulp_python_cve_2026_126984_audit import (
    PulpPythonAuditPlugin,
    is_pulp_python_version_vulnerable,
    parse_pulp_python_version,
)


def test_parse_pulp_python_version():
    assert parse_pulp_python_version("3.38.1") == (3, 38, 1)
    assert parse_pulp_python_version("3.38.2") == (3, 38, 2)
    assert parse_pulp_python_version("") is None


def test_is_pulp_python_version_vulnerable():
    assert is_pulp_python_version_vulnerable((3, 11, 9))[0] is True
    assert is_pulp_python_version_vulnerable((3, 11, 10))[0] is False
    assert is_pulp_python_version_vulnerable((3, 38, 1))[0] is True
    assert is_pulp_python_version_vulnerable((3, 38, 2))[0] is False


def test_pulp_python_run_audit():
    res_v = PulpPythonAuditPlugin("pulp.local", {"pulp_python_version": "3.38.1"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-126984" in res_v["cve"]

    res_ok = PulpPythonAuditPlugin("pulp.local", {"pulp_python_version": "3.38.2"}).run_audit()
    assert res_ok["status"] == "OK"
