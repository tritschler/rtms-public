from plugins.oracle_ebs_apex.oracle_ebs_apex_cve_2026_114925_audit import (
    OracleEbsApexAuditPlugin,
    is_oracle_ebs_apex_vulnerable,
    parse_oracle_ebs_apex_version,
)


def test_parse_oracle_ebs_apex_version():
    assert parse_oracle_ebs_apex_version("Oracle E-Business Suite 12.2.14") == ("EBS", 12, 2, 14, "12.2.14")
    assert parse_oracle_ebs_apex_version("Oracle APEX 24.2.21") == ("APEX", 24, 2, 21, "24.2.21")
    assert parse_oracle_ebs_apex_version("") is None


def test_is_oracle_ebs_apex_vulnerable():
    assert is_oracle_ebs_apex_vulnerable("EBS", 12, 2, 15)[0] is True
    assert is_oracle_ebs_apex_vulnerable("EBS", 12, 2, 16)[0] is False
    assert is_oracle_ebs_apex_vulnerable("APEX", 24, 2, 21)[0] is True
    assert is_oracle_ebs_apex_vulnerable("APEX", 24, 2, 22)[0] is False
    assert is_oracle_ebs_apex_vulnerable("APEX", 26, 2, 0)[0] is True


def test_oracle_ebs_apex_run_audit(mocker):
    plugin = OracleEbsApexAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-114925"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8000,
            "service_detected": True,
            "version": "12.2.14",
            "source": "Oracle EBS Banner",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-114925",
        },
    )
    assert plugin.run_audit("10.0.0.16", [8000])["status"] == "Vulnerable"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8000,
            "service_detected": True,
            "version": "12.2.16",
            "source": "Oracle EBS Banner",
            "is_vulnerable": False,
            "reason": "Patched",
        },
    )
    assert plugin.run_audit("10.0.0.16", [8000])["status"] == "OK"
