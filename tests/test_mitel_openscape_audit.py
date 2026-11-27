from plugins.mitel_openscape.mitel_openscape_cve_2026_137721_audit import (
    MitelOpenScapeAuditPlugin,
    is_mitel_openscape_version_vulnerable,
    parse_mitel_openscape_version,
)


def test_parse_mitel_openscape_version():
    assert parse_mitel_openscape_version("V11 R2.11") == (11, 2, 11)
    assert parse_mitel_openscape_version("V10 R1.68") == (10, 1, 68)
    assert parse_mitel_openscape_version("") is None


def test_is_mitel_openscape_version_vulnerable():
    assert is_mitel_openscape_version_vulnerable((11, 2, 11))[0] is True
    assert is_mitel_openscape_version_vulnerable((11, 2, 12))[0] is False
    assert is_mitel_openscape_version_vulnerable((10, 1, 68))[0] is True
    assert is_mitel_openscape_version_vulnerable((10, 1, 69))[0] is False


def test_mitel_openscape_run_audit():
    res_v = MitelOpenScapeAuditPlugin("openscape.local", {"openscape_version": "V11 R2.11"}).run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-137721" in res_v["cve"]
    assert "CVE-2026-137723" in res_v["cve"]
    assert "CVE-2026-137724" in res_v["cve"]

    res_ok = MitelOpenScapeAuditPlugin("openscape.local", {"openscape_version": "V11 R2.12"}).run_audit()
    assert res_ok["status"] == "OK"
