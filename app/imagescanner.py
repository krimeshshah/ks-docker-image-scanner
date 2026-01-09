from fastapi import FastAPI
import subprocess
import json

app = FastAPI()

@app.get("/scan/{image_name}")
def scan_image(image_name: str):
    sbom_cmd = ["syft", image_name, "-o", "json"]
    grype_cmd = ["grype", image_name, "-o", "json"]

    sbom = subprocess.check_output(sbom_cmd)
    vulns = subprocess.check_output(grype_cmd)

    return {
        "sbom": json.loads(sbom),
        "vulnerabilities": json.loads(vulns)
    }
