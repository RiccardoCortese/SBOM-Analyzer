import json
import requests
import os

from fastapi import APIRouter, HTTPException
from functools import lru_cache

from config import STORAGE_DIR
from services.dependency_simulator import simulate_dependency_update

router = APIRouter()


# ==========================================================
# NVD
#
# NVD viene utilizzato SOLO per il CISA KEV.
# Tutti gli altri dati della vulnerabilità vengono presi
# direttamente da Trivy.
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

    except requests.RequestException as e:

        print(f"[DEBUG NVD] Errore connessione NVD per {cve_id}: {e}", flush=True)

        return None

    if response.status_code != 200:

        print(f"[DEBUG NVD] NVD HTTP {response.status_code} per {cve_id}", flush=True)

        return None

    try:

        data = response.json()

    except ValueError:

        print(f"[DEBUG NVD] Risposta NVD non valida per {cve_id}", flush=True)

        return None

    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:

        print(f"[DEBUG NVD] CVE {cve_id} non presente in NVD", flush=True)

        return None

    return vulnerabilities[0].get("cve")


def get_nvd_cves_batch(cve_ids):

    if not cve_ids:
        return {}

    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    try:

        response = requests.get(
            nvd_url,
            params={"cveIds": ",".join(cve_ids)},
            timeout=60
        )

    except requests.RequestException as e:

        print(f"[DEBUG NVD] Errore connessione NVD: {e}", flush=True)

        return {}

    if response.status_code == 429:

        print("[DEBUG NVD] NVD HTTP 429: rate limit raggiunto.", flush=True)

        return {}

    if response.status_code != 200:

        print(f"[DEBUG NVD] NVD HTTP {response.status_code}: {response.text[:500]}", flush=True)
    
        return {}

    try:

        data = response.json()

    except ValueError:

        print("[DEBUG NVD] Risposta NVD non valida.", flush=True)

        return {}

    return {
        item["cve"]["id"]: item["cve"]
        for item in data.get("vulnerabilities", [])
        if item.get("cve", {}).get("id")
    }


# ==========================================================
# TRIVY
# ==========================================================

def get_trivy_cve(cve_id: str):

    trivy_file = os.path.join(STORAGE_DIR, "trivy_vulnerabilities.json")

    if not os.path.exists(trivy_file):

        print(f"[DEBUG TRIVY] Report non trovato: {trivy_file}", flush=True)

        return None

    try:

        with open(trivy_file, "r", encoding="utf-8") as f:
            data = json.load(f)

    except Exception as e:

        print(f"[DEBUG TRIVY] Errore lettura report: {e}", flush=True)

        return None

    cve_id = cve_id.upper()

    for result in data.get("Results", []):

        vulnerabilities = result.get("Vulnerabilities",[]) or []

        for vulnerability in vulnerabilities:

            vulnerability_id = vulnerability.get("VulnerabilityID")

            if not vulnerability_id:
                continue

            if vulnerability_id.upper() != cve_id:
                continue

            return {
                "id": vulnerability_id,

                "pkg_name": vulnerability.get("PkgName"),

                "pkg_id": vulnerability.get("PkgID"),

                "purl": vulnerability.get("PkgIdentifier", {}).get("PURL"),

                "installed_version": vulnerability.get("InstalledVersion"),

                "fixed_version": vulnerability.get("FixedVersion"),

                "status": vulnerability.get("Status"),

                "severity": vulnerability.get("Severity"),

                "severity_source": vulnerability.get("SeveritySource"),

                "title": vulnerability.get("Title"),

                "description": vulnerability.get("Description"),

                "references": vulnerability.get("References", []),

                "primary_url": vulnerability.get("PrimaryURL"),

                "published": vulnerability.get("PublishedDate"),

                "last_modified": vulnerability.get("LastModifiedDate"),

                "cwe": vulnerability.get("CweIDs", []),

                "cvss": vulnerability.get("CVSS", {}),

                "vendor_severity": vulnerability.get("VendorSeverity", {}),

                "data_source": vulnerability.get("DataSource", {}),

                "target": result.get("Target"),

                "type": result.get("Type"),

                "class": result.get("Class")
            }

    return None


# ==========================================================
# CVSS
#
# I CVSS vengono presi esclusivamente da Trivy.
# ==========================================================

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


def build_trivy_cvss(trivy_cve):

    trivy_cvss = trivy_cve.get("cvss", {}) or {}
    cvss = {}

    for source, source_data in trivy_cvss.items():

        if not isinstance(source_data, dict):
            continue

        source_name = source.upper()

        if source_data.get("V4Score") is not None:

            score = source_data["V4Score"]

            cvss.setdefault("4.0", []).append({
                "version": "4.0",
                "score": score,
                "severity": cvss_to_severity(score),
                "vector": source_data.get("V4Vector"),
                "source": source_name
            })

        if source_data.get("V3Score") is not None:

            score = source_data["V3Score"]

            cvss.setdefault("3.1", []).append({
                "version": "3.1",
                "score": score,
                "severity": cvss_to_severity(score),
                "vector": source_data.get("V3Vector"),
                "source": source_name
            })

        if source_data.get("V2Score") is not None:

            score = source_data["V2Score"]

            cvss.setdefault("2.0", []).append({
                "version": "2.0",
                "score": score,
                "severity": cvss_to_severity(score),
                "vector": source_data.get("V2Vector"),
                "source": source_name
            })

    return cvss

def get_max_cvss(cvss):

    max_cvss = None

    for metrics in cvss.values():

        for metric in metrics:

            score = metric.get("score")

            if score is None:
                continue

            if max_cvss is None or score > max_cvss["score"]:
                max_cvss = metric

    return max_cvss

# ==========================================================
# CISA KEV
#
# L'unico dato che recuperiamo da NVD.
# ==========================================================

def get_cisa_kev(nvd_cve):

    # NVD non ha trovato il CVE:
    # non possiamo stabilire se sia o meno nel CISA KEV.
    if not nvd_cve:
        return None

    for reference in nvd_cve.get("references", []):

        tags = reference.get("tags", []) or []

        if "Known Exploited Vulnerability" in tags:
            return True

    # Il CVE è stato trovato in NVD, ma non ha il tag KEV.
    return False


# ==========================================================
# MERGE TRIVY + NVD
#
# TRIVY = fonte principale
# NVD   = SOLO CISA KEV
# ==========================================================

def merge_cve_information(trivy_cve, nvd_cve):

    # ------------------------------------------------------
    # DATI CVSS DA TRIVY
    # ------------------------------------------------------

    cvss = build_trivy_cvss(trivy_cve)

    max_cvss = get_max_cvss(cvss)

    max_score = None

    if max_cvss:

        max_score = max_cvss.get("score")

    # ------------------------------------------------------
    # CWE DA TRIVY
    # ------------------------------------------------------

    cwe = list(trivy_cve.get("cwe", []) or [])

    # ------------------------------------------------------
    # RIFERIMENTI TRIVY
    # ------------------------------------------------------

    references = []

    for url in trivy_cve.get("references", []) or []:

        if isinstance(url, str):

            references.append({
                "url": url,
                "source": "Trivy",
                "tags": []
            })

        elif isinstance(url, dict):

            references.append(url)

    # ------------------------------------------------------
    # CISA KEV DA NVD
    # ------------------------------------------------------

    kev = get_cisa_kev(nvd_cve)

    # ------------------------------------------------------
    # INFORMAZIONI FINALI
    # ------------------------------------------------------

    information = {

        # Identificazione
        "id": trivy_cve.get("id"),

        "pkg_name": trivy_cve.get("pkg_name"),

        "pkg_id": trivy_cve.get("pkg_id"),

        "purl": trivy_cve.get("purl"),

        # Versioni
        "installed_version": trivy_cve.get("installed_version"),

        "fixed_version": trivy_cve.get("fixed_version"),

        # Stato
        "status": trivy_cve.get("status"),

        # Severità Trivy
        "severity": trivy_cve.get("severity"),

        "severity_source": trivy_cve.get("severity_source"),

        # Informazioni descrittive
        "title": trivy_cve.get("title"),

        "description": trivy_cve.get("description"),

        # Riferimenti
        "references": references,

        "primary_url": trivy_cve.get("primary_url"),

        # Date
        "published": trivy_cve.get("published"),

        "lastModified": trivy_cve.get("last_modified"),

        # CVSS
        "cvss": cvss,

        "max_cvss": max_cvss,

        "max_score": max_score,

        # CWE
        "cwe": cwe,

        # CISA KEV
        "kev": kev,

        # Informazioni Trivy aggiuntive
        "vendor_severity": trivy_cve.get("vendor_severity", {}),

        "data_source": trivy_cve.get("data_source", {}),

        "target": trivy_cve.get("target"),

        "type": trivy_cve.get("type"),

        "class": trivy_cve.get("class")
    }

    return information


# ==========================================================
# ENDPOINT SINGOLO CVE
# ==========================================================

@router.get("/cve/{cve_id}")
def get_cve_information(cve_id: str):

    cve_id = cve_id.upper().strip()

    if not cve_id.startswith("CVE-"):

        raise HTTPException(status_code=400, detail="ID CVE non valido.")

    print(f"Richiesta informazioni CVE: {cve_id}", flush=True)

    # ------------------------------------------------------
    # TRIVY
    # ------------------------------------------------------

    trivy_cve = get_trivy_cve(cve_id)

    if not trivy_cve:

        raise HTTPException(
            status_code=404,
            detail=(
                f"{cve_id} non trovata nel report Trivy."
            )
        )

    # ------------------------------------------------------
    # NVD
    #
    # Serve solamente per CISA KEV.
    # ------------------------------------------------------

    nvd_cve = get_nvd_cve(cve_id)

    if not nvd_cve:

        print(f"[DEBUG CVE] {cve_id} presente in Trivy ma non trovata in NVD.", flush=True)

    # ------------------------------------------------------
    # MERGE
    # ------------------------------------------------------

    information = merge_cve_information(trivy_cve, nvd_cve)

    print(
        f"[DEBUG CVE] {cve_id} "
        f"CVSS={information.get('cvss')} "
        f"MAX={information.get('max_score')} "
        f"KEV={information.get('kev')}",
        flush=True
    )

    return {
        "status": "success",

        "cve": information,

        "trivy": trivy_cve,

        "nvd": nvd_cve,

        "nvd_found": nvd_cve is not None,

        "kev": information.get(
            "kev",
            False
        )
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

        # --------------------------------------------------
        # TRIVY
        # --------------------------------------------------

        trivy_cve = get_trivy_cve(cve_id)

        if not trivy_cve:
            continue

        # --------------------------------------------------
        # NVD
        #
        # SOLO KEV
        # --------------------------------------------------

        nvd_cve = get_nvd_cve(cve_id)

        # --------------------------------------------------
        # MERGE
        # --------------------------------------------------

        information = merge_cve_information(trivy_cve, nvd_cve)

        results[cve_id] = {
            "severity": information.get("severity"),

            "installed_version": information.get("installed_version"),

            "fixed_version": information.get("fixed_version"),

            "status": information.get("status"),
            
            "cvss": information.get("cvss", {}),

            "max_cvss": information.get("max_cvss"),

            "max_score": information.get("max_score"),

            "cwe": information.get("cwe", []),

            "kev": information.get("kev", False),

            "nvd_found": nvd_cve is not None
        }

    return {
        "status": "success",
        "cves": results
    }


# ==========================================================
# RICERCA SBOM
# ==========================================================

def find_sbom_by_purl(purl: str):

    if not purl:
        return ""

    search_folders = [
        "manifests",
        "dependencies",
        "docker_sbom_steps"
    ]

    sbom_files = []

    for folder in search_folders:

        folder_path = os.path.join(STORAGE_DIR, folder)

        if not os.path.exists(folder_path):
            continue

        for root, _, files in os.walk(folder_path):

            for file in files:

                if file.endswith(".json"):

                    sbom_files.append(os.path.join(root, file))

    root_sbom = os.path.join(STORAGE_DIR, "docker_sbom.json")

    if os.path.exists(root_sbom):

        sbom_files.append(root_sbom)

    for sbom_file in sbom_files:

        try:

            with open(sbom_file, encoding="utf-8") as f:

                sbom = json.load(f)

        except Exception:

            continue

        for component in sbom.get("components", []):

            if component.get("purl") == purl:

                return sbom_file

    return ""


# ==========================================================
# SIMULAZIONE AGGIORNAMENTO
# ==========================================================

@router.get("/simulate-update")
def simulate_update_endpoint(name: str, purl: str, current_version: str, target_version: str):

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

    sbom = os.path.join(STORAGE_DIR, "final_merged_sbom.json")

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
            detail=(
                "Nessuno SBOM trovato "
                "per il PURL specificato."
            )
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