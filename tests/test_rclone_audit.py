import pytest
from plugins.rclone.rclone_cve_2026_134352_audit import (
    RcloneAuditPlugin,
    is_rclone_version_vulnerable,
    parse_rclone_version,
)


def test_parse_rclone_version():
    assert parse_rclone_version("v1.75.2") == (1, 75, 2)
    assert parse_rclone_version("1.76.0") == (1, 76, 0)
    assert parse_rclone_version("") is None


def test_is_rclone_version_vulnerable():
    assert is_rclone_version_vulnerable((1, 51, 0))[0] is True
    assert is_rclone_version_vulnerable((1, 75, 3))[0] is True
    assert is_rclone_version_vulnerable((1, 76, 0))[0] is False
    assert is_rclone_version_vulnerable((1, 50, 0))[0] is False


def test_rclone_run_audit():
    p_v = RcloneAuditPlugin("rclone.local", {"rclone_version": "1.75.2"})
    res_v = p_v.run_audit()
    assert res_v["status"] == "Vulnerable"
    assert "CVE-2026-134352" in res_v["cve"]

    p_ok = RcloneAuditPlugin("rclone.local", {"rclone_version": "1.76.0"})
    assert p_ok.run_audit()["status"] == "OK"
