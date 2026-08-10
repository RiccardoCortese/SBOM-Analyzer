import requests

from fastapi import APIRouter, HTTPException


router = APIRouter()


@router.get("/cve/{cve_id}")
def get_cve_information(cve_id: str):

    cve_id = cve_id.upper().strip()

    if not cve_id.startswith("CVE-"):
        raise HTTPException(
            status_code=400,
            detail="ID CVE non valido."
        )

    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    try:
        response = requests.get(
            nvd_url,
            params={"cveIds": cve_id},
            timeout=30
        )
    except requests.RequestException as e:
        raise HTTPException(
            status_code=502,
            detail=f"Errore durante la connessione a NVD: {e}"
        )

    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"NVD ha restituito HTTP {response.status_code}"
        )

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        raise HTTPException(
            status_code=404,
            detail=f"{cve_id} non trovato in NVD."
        )

    cve = vulnerabilities[0]["cve"]

    # ==========================
    # DESCRIZIONE
    # ==========================

    description = ""

    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            description = item.get("value", "")
            break

    # ==========================
    # CVSS
    # ==========================

    cvss = None
    metrics = cve.get("metrics", {})

    if metrics.get("cvssMetricV40"):
        cvss_data = metrics["cvssMetricV40"][0].get("cvssData", {})

        cvss = {
            "version": "4.0",
            "score": cvss_data.get("baseScore"),
            "severity": cvss_data.get("baseSeverity"),
            "vector": cvss_data.get("vectorString")
        }

    elif metrics.get("cvssMetricV31"):
        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})

        cvss = {
            "version": "3.1",
            "score": cvss_data.get("baseScore"),
            "severity": cvss_data.get("baseSeverity"),
            "vector": cvss_data.get("vectorString")
        }

    elif metrics.get("cvssMetricV30"):
        cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})

        cvss = {
            "version": "3.0",
            "score": cvss_data.get("baseScore"),
            "severity": cvss_data.get("baseSeverity"),
            "vector": cvss_data.get("vectorString")
        }

    # ==========================
    # CWE
    # ==========================

    cwe = []

    for weakness in cve.get("weaknesses", []):
        for item in weakness.get("description", []):
            value = item.get("value")

            if value and value not in cwe:
                cwe.append(value)

    # ==========================
    # RIFERIMENTI
    # ==========================

    references = []

    for reference in cve.get("references", []):
        references.append({
            "url": reference.get("url"),
            "source": reference.get("source"),
            "tags": reference.get("tags", [])
        })

    # ==========================
    # CISA KEV
    # ==========================

    is_kev = any(
        "Known Exploited Vulnerability" in reference.get("tags", [])
        for reference in references
    )

    return {
        "status": "success",
        "cve": {
            "id": cve.get("id"),
            "sourceIdentifier": cve.get("sourceIdentifier"),
            "published": cve.get("published"),
            "lastModified": cve.get("lastModified"),
            "vulnStatus": cve.get("vulnStatus"),
            "description": description,
            "cvss": cvss,
            "cwe": cwe,
            "kev": is_kev,
            "references": references
        },
        "nvd": cve
    }