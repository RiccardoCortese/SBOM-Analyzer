import requests

from fastapi import APIRouter, HTTPException
from functools import lru_cache

router = APIRouter()


# ==========================================================
# CACHE NVD
# ==========================================================

@lru_cache(maxsize=500)
def get_nvd_cve(cve_id: str):

    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    try:
        response = requests.get(nvd_url, params={"cveIds": cve_id}, timeout=30)

    except requests.RequestException:
        return None

    if response.status_code != 200:
        return None

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        return None

    return vulnerabilities[0]["cve"]

def get_nvd_severity(cve_id):
    cve = get_nvd_cve(cve_id)

    if not cve:
        return None

    metrics = cve.get("metrics", {})

    scores = []

    for version in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"]:
        for metric in metrics.get(version, []):
            if metric.get("source") == "nvd@nist.gov":
                score = metric.get("cvssData", {}).get("baseScore")

                if score is not None:
                    scores.append(score)

    if not scores:
        return None

    score = max(scores)

    if score >= 9.0:
        return "CRITICAL"

    if score >= 7.0:
        return "HIGH"

    if score >= 4.0:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "NONE"

# ==========================================================
# CVSS
# ==========================================================

def get_nvd_metric(metric_list, version):

    for metric in metric_list:

        source = metric.get("source", "")

        if source == "nvd@nist.gov":

            cvss_data = metric.get("cvssData", {})

            if cvss_data:

                return {
                    "version": version,
                    "score": cvss_data.get("baseScore"),
                    "severity": cvss_data.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString"),
                    "source": "NVD"
                }

    return None


def cvss_to_severity(score):

    if score is None:
        return "UNKNOWN"

    if score >= 9.0:
        return "CRITICAL"

    if score >= 7.0:
        return "HIGH"

    if score >= 4.0:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "NONE"


def get_metric(metric_list, version):

    # Prima cerchiamo NVD

    nvd_metric = get_nvd_metric(metric_list, version)

    if nvd_metric:
        return nvd_metric

    # Se NVD non esiste, prendiamo la prima disponibile

    if metric_list:

        metric = metric_list[0]
        cvss_data = metric.get("cvssData", {})

        return {
            "version": version,
            "score": cvss_data.get("baseScore"),
            "severity": cvss_data.get("baseSeverity"),
            "vector": cvss_data.get("vectorString"),
            "source": metric.get("source", "Unknown")
        }

    return None


# ==========================================================
# CVSS MASSIMO
# ==========================================================

def get_max_cvss(cvss):

    max_score = None
    max_cvss = None

    for version in ["4.0", "3.1", "3.0"]:

        if version not in cvss:
            continue

        score = cvss[version].get("score")

        if score is None:
            continue

        if max_score is None or score > max_score:

            max_score = score
            max_cvss = cvss[version]

    return max_cvss


# ==========================================================
# INFORMAZIONI CVE
# ==========================================================

def build_cve_information(cve):

    # ==========================
    # DESCRIZIONE
    # ==========================

    description = ""

    for item in cve.get("descriptions", []):

        if item.get("lang") == "en":

            description = item.get("value", "")
            break

    # ==========================================================
    # CVSS
    # ==========================================================

    cvss = {}
    metrics = cve.get("metrics", {})

    # ----------------------------------------------------------
    # CVSS 4.0
    # ----------------------------------------------------------

    if metrics.get("cvssMetricV40"):

        metric = get_metric(metrics["cvssMetricV40"], "4.0")

        if metric:
            cvss["4.0"] = metric

    # ----------------------------------------------------------
    # CVSS 3.1
    # ----------------------------------------------------------

    if metrics.get("cvssMetricV31"):

        metric = get_metric(metrics["cvssMetricV31"], "3.1")

        if metric:
            cvss["3.1"] = metric

    # ----------------------------------------------------------
    # CVSS 3.0
    # ----------------------------------------------------------

    if metrics.get("cvssMetricV30"):

        metric = get_metric(metrics["cvssMetricV30"], "3.0")

        if metric:
            cvss["3.0"] = metric

    # ==========================================================
    # CWE
    # ==========================================================

    cwe = []

    for weakness in cve.get("weaknesses", []):

        for item in weakness.get("description", []):

            value = item.get("value")

            if value and value not in cwe:
                cwe.append(value)

    # ==========================================================
    # RIFERIMENTI
    # ==========================================================

    references = []

    for reference in cve.get("references", []):

        references.append({
            "url": reference.get("url"),
            "source": reference.get("source"),
            "tags": reference.get("tags", [])
        })

    # ==========================================================
    # CISA KEV
    # ==========================================================

    is_kev = any(
        "Known Exploited Vulnerability" in reference.get("tags", [])
        for reference in references
    )

    # ==========================================================
    # CRITICITA' MASSIMA
    # ==========================================================

    max_cvss = get_max_cvss(cvss)

    if max_cvss:

        max_score = max_cvss.get("score")
        severity = cvss_to_severity(max_score)

    else:

        max_score = None
        severity = "UNKNOWN"

    return {
        "id": cve.get("id"),
        "sourceIdentifier": cve.get("sourceIdentifier"),
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "vulnStatus": cve.get("vulnStatus"),
        "description": description,
        "cvss": cvss,
        "max_cvss": max_cvss,
        "max_score": max_score,
        "severity": severity,
        "cwe": cwe,
        "kev": is_kev,
        "references": references
    }


# ==========================================================
# ENDPOINT SINGOLO CVE
# ==========================================================

@router.get("/cve/{cve_id}")
def get_cve_information(cve_id: str):

    cve_id = cve_id.upper().strip()

    if not cve_id.startswith("CVE-"):

        raise HTTPException(
            status_code=400,
            detail="ID CVE non valido."
        )

    print(f"Richiesta informazioni CVE: {cve_id}")

    cve = get_nvd_cve(cve_id)

    if not cve:

        raise HTTPException(
            status_code=404,
            detail=f"{cve_id} non trovato in NVD."
        )

    information = build_cve_information(cve)

    return {
        "status": "success",
        "cve": information,
        "nvd": cve
    }


# ==========================================================
# ENDPOINT MULTIPLI CVE
# ==========================================================

@router.get("/cves")
def get_cves_information(cve_ids: str):

    ids = [
        cve.strip().upper()
        for cve in cve_ids.split(",")
        if cve.strip()
    ]

    results = {}

    for cve_id in ids:

        if not cve_id.startswith("CVE-"):
            continue

        print(f"Richiesta informazioni CVE: {cve_id}")

        cve = get_nvd_cve(cve_id)

        if not cve:
            continue

        information = build_cve_information(cve)

        results[cve_id] = {
            "cvss": information["cvss"],
            "max_cvss": information["max_cvss"],
            "max_score": information["max_score"],
            "severity": information["severity"]
        }

    return {
        "status": "success",
        "cves": results
    }