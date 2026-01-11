import json
import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException
import subprocess

from app.main import  (
    app,
    run_cmd,
    extract_packages,
    extract_vulns,
)


client = TestClient(app)

@pytest.fixture
def mock_sbom():
    return {
        "artifacts": [
            {
                "name": "openssl",
                "version": "1.1.1",
                "type": "apk",
                "licenses": [{"value": "OpenSSL"}],
            },
            {
                "name": "curl",
                "version": "8.0.0",
                "type": "apk",
                "licenses": [],
            },
        ]
    }

@pytest.fixture
def mock_grype():
    return {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-1234",
                    "severity": "High",
                    "fix": {"versions": ["1.1.2"]},
                },
                "artifact": {
                    "name": "openssl",
                    "version": "1.1.1",
                },
            },
            {
                "vulnerability": {
                    "id": "CVE-2023-9999",
                    "severity": "Low",
                    "fix": {},
                },
                "artifact": {
                    "name": "curl",
                    "version": "8.0.0",
                },
            },
        ]
    }


def test_extract_packages(mock_sbom):
    packages = extract_packages(mock_sbom)

    assert len(packages) == 2
    assert packages[0]["name"] == "openssl"
    assert packages[1]["name"] == "curl"
    assert packages[0]["licenses"] == ["OpenSSL"]
    assert packages[1]["licenses"] == []

def test_extract_vulns(mock_grype):
    vulns, severity = extract_vulns(mock_grype)

    assert len(vulns) == 2
    assert severity["High"] == 1
    assert severity["Low"] == 1

    assert vulns[0]["fix_available"] is True
    assert vulns[1]["fix_available"] is False

def test_run_cmd_success(mocker):
    mocker.patch(
        "subprocess.check_output",
        return_value=json.dumps({"key": "value"}).encode(),
    )

    result = run_cmd(["fake", "command"])
    assert result == {"key": "value"}


def test_run_cmd_failure(mocker):
    mocker.patch(
        "subprocess.check_output",
        side_effect=subprocess.CalledProcessError(
            returncode=1,
            cmd=["bad", "command"],
            output=b"something went wrong",
        ),
    )

    with pytest.raises(HTTPException) as exc:
        run_cmd(["bad", "command"])

    assert exc.value.status_code == 500
    assert "Command failed" in exc.value.detail





