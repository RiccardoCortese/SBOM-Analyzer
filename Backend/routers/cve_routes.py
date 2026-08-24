import json
import requests
import os

from fastapi import APIRouter, HTTPException
from functools import lru_cache

from config import STORAGE_DIR
from services.dependency_simulator import simulate_dependency_update

router = APIRouter()


# ==========================================================
# CACHE NVD
# ==========================================================
@lru_cache(maxsize=500)
def get_nvd_cve(cve_id: str):

    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    try:

        response = requests.get(
            nvd_url,
            params={"cveIds": cve_id},
            timeout=30
        )
        
        print(
            f"[DEBUG NVD] CVE={cve_id} "
            f"status={response.status_code} "
            f"url={response.url}",
            flush=True
        )

    except requests.RequestException as e:

        print(
            f"[DEBUG NVD] Errore connessione NVD per {cve_id}: {e}",
            flush=True
        )

        return None

    if response.status_code != 200:

        print(
            f"[DEBUG NVD] NVD HTTP {response.status_code} per {cve_id}: "
            f"{response.text[:500]}",
            flush=True
        )

        return None

    try:

        data = response.json()

    except ValueError as e:

        print(
            f"[DEBUG NVD] Risposta NVD non valida per {cve_id}: {e}",
            flush=True
        )

        return None

    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:

        print(
            f"[DEBUG NVD] CVE {cve_id} non presente. "
            f"totalResults={data.get('totalResults')}",
            flush=True
        )

        return None

    return vulnerabilities[0]["cve"]


def get_nvd_cves_batch(cve_ids):

    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    try:

        response = requests.get(
            nvd_url,
            params={"cveIds": ",".join(cve_ids)},
            timeout=60
        )

    except requests.RequestException as e:

        print(
            f"[DEBUG NVD] Errore connessione NVD: {e}",
            flush=True
        )

        return {}

    if response.status_code == 429:

        print(
            f"[DEBUG NVD] NVD HTTP 429: rate limit raggiunto.",
            flush=True
        )

        return {}

    if response.status_code != 200:

        print(
            f"[DEBUG NVD] NVD HTTP {response.status_code}: "
            f"{response.text[:500]}",
            flush=True
        )

        return {}

    try:

        data = response.json()

    except ValueError as e:

        print(
            f"[DEBUG NVD] Risposta NVD non valida: {e}",
            flush=True
        )

        return {}

    return {
        item["cve"]["id"]: item["cve"]
        for item in data.get("vulnerabilities", [])
    }


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

def find_sbom_by_purl(purl: str):

    if not purl:
        return ""

    search_folders = [
        "manifests",
        "dependencies",
        "docker_sbom_steps"
    ]

    sbom_files = []

    # Cerca negli SBOM delle cartelle
    for folder in search_folders:

        folder_path = os.path.join(
            STORAGE_DIR,
            folder
        )

        if not os.path.exists(folder_path):
            continue

        for root, _, files in os.walk(folder_path):

            for file in files:

                if file.endswith(".json"):

                    sbom_files.append(
                        os.path.join(root, file)
                    )

    # Cerca anche docker_sbom.json nella root
    root_sbom = os.path.join(
        STORAGE_DIR,
        "docker_sbom.json"
    )

    if os.path.exists(root_sbom):

        sbom_files.append(root_sbom)

    # Cerca il PURL
    for sbom_file in sbom_files:

        try:

            with open(
                sbom_file,
                encoding="utf-8"
            ) as f:

                sbom = json.load(f)

        except Exception:

            continue

        for component in sbom.get("components", []):

            if component.get("purl") == purl:

                return sbom_file

    return ""
@router.get("/simulate-update")
def simulate_update_endpoint(
    name: str,
    purl: str,
    current_version: str,
    target_version: str
):

    if not target_version:

        raise HTTPException(
            status_code=400,
            detail="Versione target non specificata."
        )

    if not purl:

        raise HTTPException(
            status_code=400,
            detail="PURL non specificato."
        )

    # Cerca lo SBOM corrispondente al PURL
    sbom = os.path.join(STORAGE_DIR, "final_merged_sbom.json")
    #sbom = find_sbom_by_purl(purl)
    print(
        f"[DEBUG SIMULATE] "
        f"name={name} "
        f"purl={purl} "
        f"sbom={sbom}",
        flush=True
    )

    if not sbom:

        raise HTTPException(
            status_code=404,
            detail="Nessuno SBOM trovato per il PURL specificato."
        )

    if not os.path.exists(sbom):

        raise HTTPException(
            status_code=404,
            detail="SBOM non trovato."
        )

    result = simulate_dependency_update(
        purl=purl,
        current_version=current_version,
        target_version=target_version,
        sbom_file=sbom
    )

    if not result.get("success"):

        raise HTTPException(
            status_code=400,
            detail=result.get(
                "error",
                "Errore durante la simulazione."
            )
        )

    return result