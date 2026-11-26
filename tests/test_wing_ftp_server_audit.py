import pytest
from plugins.wing_ftp_server.wing_ftp_server_cve_2026_135171_audit import (
    WingFTPServerAuditPlugin,
    is_wing_ftp_version_vulnerable,
    parse_wing_ftp_version,
)


def test_parse_wing_ftp_version():
    assert parse_wing_ftp_version("8.2.7") == (8, 2, 7)
    assert parse_wing_ftp_version("Wing FTP Server/8.2.8") == (8, 2, 8)
    assert parse_wing_ftp_version("") is None


def test_is_wing_ftp_version_vulnerable():
    assert is_wing_ftp_version_vulnerable((8, 2, 7))[0] is True
    assert is_wing_ftp_version_vulnerable((8, 2, 8))[0] is False


def test_wing_ftp_run_audit():
    p_v = WingFTPServerAuditPlugin("wing.local", {"wing_ftp_version": "8.2.7"})
    res_v = p_v.run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-135171" in res_v["cve"]

    p_ok = WingFTPServerAuditPlugin("wing.local", {"wing_ftp_version": "8.2.8"})
    assert p_ok.run_audit()["status"] == "OK"
