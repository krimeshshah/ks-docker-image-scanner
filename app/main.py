from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from collections import Counter
from datetime import datetime, timezone

import subprocess
import json

app = FastAPI(
    title="KS Docker Image Scanner",
    description="SBOM and vulnerability scanner using Syft and Grype",
    version="1.0.0",
)

# Utility functions
# -----------------------------

def run_cmd(cmd: list[str]) -> dict:
    """
    Run a shell command and return parsed JSON output.
    """
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return json.loads(output)
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Command failed: {' '.join(cmd)}\n{e.output.decode()}",
        )
    
def extract_packages(sbom: dict) -> list[dict]:
    """
    Extract package and license information from Syft SBOM.
    """
    packages = []

    for pkg in sbom.get("artifacts", []):
        packages.append(
            {
                "name": pkg.get("name"),
                "version": pkg.get("version"),
                "type": pkg.get("type"),
                "licenses": [
                    lic.get("value")
                    for lic in pkg.get("licenses", [])
                    if lic.get("value")
                ],
            }
        )

    return packages


def extract_vulns(grype: dict):
    """
    Extract vulnerability details and severity summary from Grype output.
    """
    vulns = []

    for match in grype.get("matches", []):
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        vulns.append(
            {
                "id": vulnerability.get("id"),
                "severity": vulnerability.get("severity"),
                "package": artifact.get("name"),
                "version": artifact.get("version"),
                "fix_available": bool(vulnerability.get("fix", {}).get("versions")),
            }
        )

    severity_summary = Counter(v["severity"] for v in vulns if v["severity"])

    return vulns, dict(severity_summary)


# -----------------------------
# API routes
# -----------------------------

@app.get("/")
def home():
    return {
        "message": "KS Docker Image Scanner API",
        "docs": "/docs",
    }


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)


@app.get("/scan/{image}")
def scan_image(image: str):
    """
    Scan a Docker image for SBOM and vulnerabilities.
    """
    datetime.now(timezone.utc)

    timestamp = 1571595618.0
    datetime.fromtimestamp(timestamp, timezone.utc) 

    # Run Syft and Grype
    sbom = run_cmd(["syft", image, "-o", "json"])
    grype = run_cmd(["grype", image, "-o", "json"])

    # Normalize outputs
    packages = extract_packages(sbom)
    vulns, severity = extract_vulns(grype)

    # Simple risk logic (can evolve later)
    if severity.get("Critical", 0) > 0:
        risk = "CRITICAL"
    elif severity.get("High", 0) > 0:
        risk = "HIGH"
    elif severity.get("Medium", 0) > 0:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "image": image,
        "scan_time": scan_time,
        "sbom": {
            "packages_detected": len(packages),
            "packages": packages,
        },
        "vulnerabilities": {
            "total": len(vulns),
            "severity": severity,
            "details": vulns,
        },
        "risk": risk,
    }






