from plugins.oracle_database.oracle_database_cve_2026_114848_audit import (
    OracleDatabaseAuditPlugin,
    is_oracle_db_version_vulnerable,
    parse_oracle_db_version,
)


def test_parse_oracle_db_version():
    assert parse_oracle_db_version("Oracle Database 19.24.0") == (19, 24, 0, "19.24.0")
    assert parse_oracle_db_version("Oracle Database 23.26.3") == (23, 26, 3, "23.26.3")
    assert parse_oracle_db_version("") is None


def test_is_oracle_db_version_vulnerable():
    assert is_oracle_db_version_vulnerable(19, 33, 0)[0] is True
    assert is_oracle_db_version_vulnerable(19, 34, 0)[0] is False
    assert is_oracle_db_version_vulnerable(21, 24, 0)[0] is True
    assert is_oracle_db_version_vulnerable(23, 26, 3)[0] is True
    assert is_oracle_db_version_vulnerable(23, 26, 4)[0] is False


def test_oracle_db_run_audit(mocker):
    plugin = OracleDatabaseAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-114848"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 1521,
            "service_detected": True,
            "version": "19.22.0",
            "source": "Oracle TNS/EM",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-114848",
        },
    )
    assert plugin.run_audit("10.0.0.12", [1521])["status"] == "Vulnerable"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 1521,
            "service_detected": True,
            "version": "19.34.0",
            "source": "Oracle TNS/EM",
            "is_vulnerable": False,
            "reason": "Patched",
        },
    )
    assert plugin.run_audit("10.0.0.12", [1521])["status"] == "OK"
