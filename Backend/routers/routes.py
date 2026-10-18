from datetime import datetime
import hashlib
import os
import json
import shutil
import subprocess
import fnmatch
import stat
import glob as glb
import re
import requests
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from typing import Optional
from collections import defaultdict 
from urllib.parse import unquote, quote
from packageurl import PackageURL
from concurrent.futures import ThreadPoolExecutor, as_completed


from config import STORAGE_DIR, STANDARD_FILE_ANALYZED
from utils.tools import get_cyclonedx_path
from services.github_service import trigger_github_action, wait_and_download_artifacts
from services.sbom_parser import (
    complete_graph_with_deps_dev, get_docker_analysis, generate_graphs_for_folder, 
    build_universal_hierarchy, get_dependency_weight
)
from services.component_search import search_component, build_component_graph
from utils.tools import get_trivy_path
from routers.cve_routes import router as cve_router
from routers.cve_routes import get_nvd_cves_batch
from services.provenance_service import (find_dependency_chain, load_docker_step_sboms, find_component_origins, load_manifest_components, save_non_declared_vulnerable_components, save_not_declared_components)
from services.source_dependencies import (analyze_source_components)

router = APIRouter()

router.include_router(cve_router)
# ============================================================
# Gestore per rimuovere file in sola lettura durante la pulizia della cartella di storage
# ============================================================
    
def remove_readonly(func, path, excinfo):
    os.chmod(path, stat.S_IWRITE)
    func(path)

# ============================================================
# ACQUISIZIONE E SALVATAGGIO IN MEMORIA SERVER di file JSON manuali o generati
# ============================================================

@router.post("/upload-sbom")
async def upload_sbom(
    repo_url: Optional[str] = Form(None), # Necessario per clonare
    branch: Optional[str] = Form(None), # Necessario per clonare
    dockerfile_path: Optional[str] = Form(None), # Necessario per clonare
):
    # pulizia della cartella di storage per evitare conflitti con file precedenti
    if os.path.exists(STORAGE_DIR):
        shutil.rmtree(STORAGE_DIR, onerror=remove_readonly)
    os.makedirs(STORAGE_DIR, exist_ok=True)
    
    if not repo_url:
        raise HTTPException(400, "URL repository mancante.")
        
    tmp_clone = os.path.join(STORAGE_DIR, "tmp_clone")
    try:
        GIT_BASE = ["git", "-c", "core.longpaths=true", "clone", "--depth", "1"]

        cmd = list(GIT_BASE)
        if branch:
            cmd += ["--branch", branch]
        cmd += [repo_url, tmp_clone]

        result = subprocess.run(cmd)

        if result.returncode != 0:
            # Clone parziale (es. checkout fallito su alcuni file): lo tengo se il repo c'è
            if os.path.isdir(os.path.join(tmp_clone, ".git")):
                print("[WARNING] Checkout parziale, proseguo con i file disponibili.")
            else:
                # Clone fallito del tutto (es. branch inesistente): riprovo senza --branch
                shutil.rmtree(tmp_clone, onerror=remove_readonly, ignore_errors=True)
                subprocess.run(GIT_BASE + [repo_url, tmp_clone], check=True)
                    
        found_files = []
        # Questi sono i pattern di file "standard" che consideriamo validi per l'analisi delle dipendenze 
        valid_patterns = ["requirements.txt", "pyproject.toml", "setup.py", "*.lock", "pom.xml", "build.gradle", "build.gradle.kts"]
        
        for root, _, files in os.walk(tmp_clone):
            for f in files:
                if any(fnmatch.fnmatch(f, pattern) for pattern in valid_patterns):
                    rel_path = os.path.relpath(root, tmp_clone).replace(os.sep, "_")
                    dest_name = f"{rel_path}_{f}" if rel_path != "." else f
                    shutil.copy(
                        os.path.join(root, f),
                        os.path.join(STORAGE_DIR, dest_name)
                    )
                    found_files.append(dest_name)
                    
        # Cerco il Dockerfile per estrarre i comandi di installazione e le immagini di base, prendendo il path da dockerfile_path
        docker_content = None
        if dockerfile_path:
            dockerfile_full_path = os.path.join(tmp_clone, dockerfile_path)
            if os.path.exists(dockerfile_full_path):
                with open(dockerfile_full_path, "r", encoding="utf-8") as df:
                    docker_content = df.read()
        
        if not found_files:
            raise HTTPException(400, "Nessun file di dipendenze rilevato.")
            
        with open(os.path.join(STORAGE_DIR, "discovered_files.json"), "w") as f:
            json.dump(found_files, f)
        with open(os.path.join(STORAGE_DIR, "upload_config.txt"), "w", encoding="utf-8") as f:
            json.dump({
                "repo_url": repo_url,
                "branch": branch,
                "dockerfile_path": dockerfile_path or "Dockerfile",
            }, f)
        
        result = get_docker_analysis(docker_content, tmp_clone) if docker_content else {"steps": [], "images": [], "diffs": [], "artifacts": [], "yara": [], "removed_components": []}

        images = result["images"]

        # Salva il risultato cumulativo
        removed_path = os.path.join(STORAGE_DIR, "removed_components.json")

        with open(removed_path, "w", encoding="utf-8") as f:
            json.dump(result["removed_components"], f , indent=4, ensure_ascii=False)

        return {
            "status": "success", 
            "files": found_files, 
            "steps": result["steps"],
            "images": images,
            "diffs": result["diffs"],
            "removed_components": result.get("removed_components", []),
            "artifacts": result.get("artifacts", []),
            "yara": result.get("yara", [])
        }
        
    finally:
        shutil.rmtree(tmp_clone, onerror=remove_readonly, ignore_errors=True)

# ============================================================
# Recupero dei file scoperti durante la fase di discovery per visualizzazione nel frontend
# ============================================================

@router.get("/get-discovered-files")
def get_discovered_files():

    path = os.path.join(STORAGE_DIR, "discovered_files.json")
    
    if not os.path.exists(path):
        # Se non esiste ancora, ritorniamo una lista vuota o un errore
        return []
    
    try:
        with open(path, "r") as f:
            data = json.load(f)
            return data
    except Exception as e:
        # In caso di errore di lettura, restituiamo un errore gestibile
        raise HTTPException(status_code=500, detail=f"Errore nella lettura dei file trovati: {str(e)}")


# ============================================================
# ANALISI SPECIFICA DI UN SINGOLO FILE TROVATO NEL DOCKERFILE
# ============================================================

# ============================================================
# FUNZIONE DI SUPPORTO
# ============================================================
def to_owner_repo(repo_url: str) -> str:
    """https://github.com/owner/repo(.git) -> owner/repo"""
    match = re.search(r"github\.com/([^/]+)/([^/?#]+)", repo_url or "")
    return f"{match.group(1)}/{match.group(2).replace('.git', '')}" if match else (repo_url or "")
 
def run_standard_sbom_action(repo_url, branch, format):
    print(f"[DEBUG] Avvio analisi per {format} su {repo_url} (branch: {branch})", flush=True)
    
    match = re.search(r"github\.com/([^/]+)/([^/?#]+)", repo_url)
    owner_repo = f"{match.group(1)}/{match.group(2).replace('.git', '')}" if match else repo_url

    inputs = {
        "src_repository": owner_repo,
        "src_branch": branch,
        "format": format
    }

    action_info = trigger_github_action("sbom_static.yml", inputs)
    
    if not action_info:
        raise HTTPException(status_code=500, detail="Il trigger della GitHub Action è fallito.")

    # Scarica artefatti
    wait_and_download_artifacts(action_info["id"], STORAGE_DIR)

    # Mappatura file
    mapping = {
        "requirements": "trivy_requirements.json",
        "poetry": "trivy_poetry.json",
        "pyproject": "trivy_pyproject.json",
        "uv": "trivy_uv.json",
        "maven": "trivy_maven.json",
        "gradle": "trivy_gradle.json",
    }

    if format not in mapping:
        print("B")
        raise HTTPException(status_code=400, detail="File di dipendenze non supportato")
        
    target_file = os.path.join(STORAGE_DIR, "manifests", mapping[format])

    if not os.path.exists(target_file):
        raise HTTPException(status_code=404, detail="File SBOM non trovato dopo la scansione.")

    # Leggiamo il JSON per passarlo al frontend
    with open(target_file, "r", encoding="utf-8") as f:
        content = json.load(f)

    return {
        "file_name": format,
        "target_file": target_file,
        "github_run_url": action_info["html_url"],
        "content": content
    }
    
@router.post("/analyze-standard-file")
async def analyze_standard_file(
    format: str = Form(...), 
    repo_url: str = Form(...),
    branch: str = Form(...)
):
    global STANDARD_FILE_ANALYZED
    STANDARD_FILE_ANALYZED = format  # Aggiorniamo la variabile globale con il formato selezionato
    # Logica per gestire "Entrambi"
    files_da_analizzare = []
    if format == "Entrambi":
        files_da_analizzare = ["uv", "poetry", "pom", "gradle"] # Aggiungi quelli che vuoi
    else:
        if format not in ["requirements", "poetry", "pyproject.toml", "poetry.lock", "requirements.txt", "uv.lock", "pom.xml", "build.gradle", "build.gradle.kts"]:
            print("A")
            raise HTTPException(status_code=400, detail="Formato non supportato per l'analisi standard.")
        elif format == "requirements.txt":
            files_da_analizzare = ["requirements"]
        elif format == "pyproject.toml" or format == "poetry.lock":
            files_da_analizzare = ["poetry"]
        elif format == "uv.lock":
            files_da_analizzare = ["uv"]
        elif format == "pom.xml":
            files_da_analizzare = ["maven"]
        elif format in ["build.gradle", "build.gradle.kts"]:
            files_da_analizzare = ["gradle"]

    results = []
    
    # Eseguiamo l'analisi per ogni file richiesto
    for f_name in files_da_analizzare:
        try:
            # Chiamiamo la funzione che esegue la Action e scarica l'artefatto
            risultato = run_standard_sbom_action(repo_url, branch, f_name)
            results.append(risultato)
        except Exception as e:
            print(f"[ERROR] Errore durante l'analisi di {f_name}: {str(e)}", flush=True)
            raise HTTPException(status_code=500, detail=f"Errore durante l'analisi di {f_name}: {str(e)}")

    # Ritorna la lista dei risultati
    return {"status": "success", "data": results, "type": "standard"}

# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# IN CASO MODIFICARE QUESTA FUNZIONE PER AGGIUNGERE NUOVI TIPI DI FILE O FORMATI DI DIPENDENZE
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# ============================================================
# ANALISI COMPONENTI DEPENDENCIES.JSON IN PARALLELO (con github action remota) e generazione SBOM per singole dipendenze
# ============================================================

@router.post("/analyze-custom-file")
def analyze_custom_file(
    docker_image_tag_custom = Form(None),
    vuln_type_custom = Form("os,library")
):
    os.makedirs(os.path.join(STORAGE_DIR, "manifests"), exist_ok=True)
    os.makedirs(os.path.join(STORAGE_DIR, "dependencies"), exist_ok=True)
    
    print(f"[BACKEND] Avvio pipeline Docker cusotm per l'immagine: {docker_image_tag_custom}", flush=True)
    
    # Allineamento Input con la tua GitHub Action (image_repository)
    docker_inputs = {
        "image_repository": docker_image_tag_custom,
        "src_vuln_type": vuln_type_custom
    }
    
    try:
        docker_action_info_custom = trigger_github_action("sbom_dockerfile_custom.yml", docker_inputs) 
    except Exception as e:
        raise HTTPException(500, f"Impossibile avviare la pipeline Docker remota: {str(e)}")
    
    
    # Attesa completamento e download dello ZIP (estratto in STORAGE_DIR)
    success = wait_and_download_artifacts(docker_action_info_custom["id"], STORAGE_DIR)
    if not success:
        raise HTTPException(500, "Pipeline completata ma nessun artifact trovato.")
        
    #cambio "\" e ":" in "_" per evitare problemi di path
    docker_image_tag_custom = re.sub(r'[\\/:]', '_', docker_image_tag_custom)
    
    file_name = docker_image_tag_custom + "-custom-docker-SBOM.json"
    # Scansione dei file SBOM generati e caricamento in memoria per la visualizzazione
    file_path = os.path.join(STORAGE_DIR, "dependencies", file_name)
    print (f"[DEBUG] Tentativo di apertura del file: {file_path}", flush=True)
    if not os.path.exists(file_path):
        print(f"[ERROR] File SBOM generato non trovato: {file_path}", flush=True)
        raise HTTPException(500, f"File SBOM generato non trovato: {file_path}")
    
    with open(file_path, "r", encoding="utf-8") as f:
        content = json.load(f)
    
    # Generazione dei dati per la visualizzazione del grafo
    graph_results = {}
    graph_results.update(generate_graphs_for_folder(os.path.join(STORAGE_DIR, "manifests")))
    graph_results.update(generate_graphs_for_folder(os.path.join(STORAGE_DIR, "dependencies")))
    
    data = {
        "filename": file_name,
        "content": content,
        "github_run_url": docker_action_info_custom["html_url"],
    }
        
    return {
        "status": "success",
        "data": data,
        "graphs": graph_results
    }

# ============================================================
# MERGE DEI FILE SBOM TROVATI NELLE CARTELLE "manifests" e "dependencies" IN UN UNICO FILE SBOM FINALE
# ============================================================

@router.get("/merge-artifacts")
def merge_artifacts(include_removed: bool = False):
    # Recupera tutti i file JSON per il merge
    files_to_merge = (
        glb.glob(os.path.join(STORAGE_DIR, "manifests", "*.json"))
        + glb.glob(os.path.join(STORAGE_DIR, "dependencies", "*.json"))
        + glb.glob(os.path.join(STORAGE_DIR, "docker_sbom_steps", "*.json"))
    )

    removed_path = os.path.join(STORAGE_DIR, "removed_components.json")

    if os.path.exists(removed_path):
        with open(removed_path, "r", encoding="utf-8") as f:
            components_to_remove = json.load(f)
    else:
        components_to_remove = []

    print(f"[DEBUG] Components to remove: {len(components_to_remove)}", flush=True)
    if not files_to_merge:
        raise HTTPException(
            status_code=400,
            detail="Nessun file SBOM trovato per il merge."
        )

    final_sbom = os.path.join(STORAGE_DIR, "final_merged_sbom.json")
    cyclonedx_exe = get_cyclonedx_path()

    if not os.path.exists(cyclonedx_exe):
        raise HTTPException(
            status_code=500,
            detail="Tool CycloneDX CLI non trovato. Esegui il setup del binario."
        )

    subprocess.run([cyclonedx_exe, "--version"], check=True)

    merge_cmd = (
        [cyclonedx_exe, "merge", "--input-files"]
        + files_to_merge
        + ["--output-file", final_sbom]
    )

    try:
        subprocess.run(merge_cmd, check=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Errore durante il merge CycloneDX: {e}"
        )

    # Escludi le dipendenze rimosse solo se richiesto
    if not include_removed and components_to_remove:
        with open(final_sbom, "r", encoding="utf-8") as f:
            merged_content = json.load(f)

        removed_purls = {
            comp.get("purl")
            for comp in components_to_remove
            if comp.get("purl")
        }

        merged_content["components"] = [
            comp
            for comp in merged_content.get("components", [])
            if comp.get("purl") not in removed_purls
        ]

        with open(final_sbom, "w", encoding="utf-8") as f:
            json.dump(merged_content, f, indent=2, ensure_ascii=False)

    with open(final_sbom, "r", encoding="utf-8") as f:
        content = json.load(f)

    return {
        "status": "success",
        "data": content,
        "merged_file": final_sbom
    }


# ============================================================
# SCANSIONE DEI COMPONENTI PER DEFINIRE LA PROVENIENZA E LA STORIA DELLE DIPENDENZE 
# ============================================================

@router.get("/component-provenance-dockerfile")
def component_provenance():

    step_sboms = load_docker_step_sboms(STORAGE_DIR)

    docker_origins = find_component_origins(step_sboms)

    manifest_components, dependency_map, direct_purls= load_manifest_components(STORAGE_DIR)

    for purl, component in docker_origins.items():

        chain = find_dependency_chain(
            purl,
            dependency_map
        )

        component["dependency_chain"] = chain or []

        if chain and len(chain) >= 2:

            parent_purl = chain[-2]

            parent_component = (
                manifest_components.get(parent_purl)
            )

            if parent_component:
                component["derived_from"] = parent_component.get(
                    "name",
                    parent_purl
                )
            else:
                component["derived_from"] = parent_purl

        else:
            component["derived_from"] = None

    return {
        "status": "success",
        "manifest_components": manifest_components,
        "docker_components": docker_origins
    }

# ============================================================
# ANALISI DELLA PROVENIENZA DEI COMPONENTI TROVATI NEI FILE DI DIPENDENZE (requirements.txt, pyproject.toml, ecc.)
# ============================================================    
    
@router.get("/source-component-analysis")
def source_component_analysis():

    result = analyze_source_components(STORAGE_DIR)
    
    #print(f"Source component analysis: {result}", flush=True)

    if result.get("status") == "error":
        return result

    # Salva i componenti non dichiarati
    save_not_declared_components(STORAGE_DIR, result.get("not_declared", []))


    return result

# ============================================================
# ANALISI DEI COMPONENTI NON DICHIARATI CON VULNERABILITÀ
# ============================================================

@router.get("/non-declared-vulnerable-components")
def non_declared_vulnerable_components():

    result = save_non_declared_vulnerable_components(
        STORAGE_DIR
    )

    if result is None:
        return {
            "status": "error",
            "message": "Impossibile calcolare i componenti vulnerabili."
        }

    return {
        "status": "success",

        # ====================================================
        # COMPONENTI VULNERABILI TOTALI
        # ====================================================

        "total_vulnerable_components": result.get(
            "total_vulnerable_components",
            0
        ),

        # ====================================================
        # COMPONENTI NON DICHIARATI VULNERABILI
        # ====================================================

        "non_declared_vulnerable_components": result.get(
            "count",
            0
        ),

        # ====================================================
        # UNKNOWN
        # ====================================================

        "unknown_vulnerable_components": result.get(
            "unknown_vulnerable_components",
            []
        ),

        "unknown_vulnerable_count": result.get(
            "unknown_vulnerable_count",
            0
        ),

        # ====================================================
        # TRANSITIVE UNKNOWN
        # ====================================================

        "transitive_unknown_vulnerable_components": result.get(
            "transitive_unknown_vulnerable_components",
            []
        ),

        "transitive_unknown_vulnerable_count": result.get(
            "transitive_unknown_vulnerable_count",
            0
        ),

        # ====================================================
        # UNKNOWN + TRANSITIVE UNKNOWN
        # ====================================================

        "unknown_or_transitive_unknown_count": result.get(
            "unknown_or_transitive_unknown_count",
            0
        ),

        "percentage_unknown_or_transitive_unknown": result.get(
            "percentage_unknown_or_transitive_unknown",
            0
        ),

        # ====================================================
        # COMPONENTI NON DICHIARATI VULNERABILI
        # ====================================================

        "components": result.get(
            "components",
            []
        )
    }

# ============================================================
# SCAN VULNERABILITIES SULLO SBOM UNIFICATO DOPO IL MERGE (tramite Trivy)
# ===========================================================

@router.get("/scan-merged-sbom")
def scan_merged_sbom():
    # SBOM generato dal merge precedente
    final_sbom = os.path.join(STORAGE_DIR, "final_merged_sbom.json")

    if not os.path.exists(final_sbom):
        raise HTTPException(
            status_code=404,
            detail="SBOM finale non trovato. Eseguire prima il merge.",
        )

    # percorso trivy
    trivy_exe = get_trivy_path()

    if not os.path.exists(trivy_exe):
        raise HTTPException(status_code=500, detail="Trivy non trovato.")

    # output report vulnerabilità
    vulnerability_report = os.path.join(
        STORAGE_DIR, "trivy_vulnerabilities.json"
    )
    
    with open(final_sbom, "rb") as f:
        sbom_hash = hashlib.sha256(f.read()).hexdigest()

    print(f"[TRIVY] SHA256 final_merged_sbom: {sbom_hash}", flush=True)

    command = [
        trivy_exe,
        "sbom",
        "--list-all-pkgs",
        "--format", "json",
        "--output", vulnerability_report,
        final_sbom,
    ]
    
    print("[TRIVY] Versione Trivy:", flush=True)

    version_result = subprocess.run(
        [trivy_exe, "version"],
        capture_output=True,
        text=True
    )

    print(version_result.stdout, flush=True)
    print(version_result.stderr, flush=True)

    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Errore durante scansione Trivy: {e.stderr}",
        )
    
    with open(vulnerability_report, "rb") as f:
        report_hash = hashlib.sha256(f.read()).hexdigest()

    print(
        f"[TRIVY] SHA256 trivy_vulnerabilities.json: {report_hash}",
        flush=True,
    )
    
    debug_report = os.path.join(
        STORAGE_DIR,
        f"trivy_debug_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
    )

    shutil.copy2(vulnerability_report, debug_report)

    print(
        f"[TRIVY DEBUG] Report copiato in: {debug_report}",
        flush=True,
    )

    # controllo output
    if not os.path.exists(vulnerability_report):
        raise HTTPException(
            status_code=500, detail="Report Trivy non generato."
        )

    # carica risultato
    with open(vulnerability_report, "r", encoding="utf-8") as f:
        report = json.load(f)

    # ==========================================================
    # CLASSIFICAZIONE DIPENDENZE (Normalizzando i PURL)
    # ==========================================================
    analysis = analyze_source_components(STORAGE_DIR)
    dependency_classification = {}

    if analysis.get("status") == "success":
        for component in analysis.get("declared", []):
            purl = component.get("purl")
            if purl:
                # Normalizziamo rimuovendo eventuali parametri ?...
                base_purl = purl.split("?")[0]
                dependency_classification[base_purl] = "direct"

        for component in analysis.get("not_declared", []):
            purl = component.get("purl")
            classification = component.get("classification")
            if purl:
                base_purl = purl.split("?")[0]
                dependency_classification[base_purl] = classification

    # ==========================================================
    # RECUPERO SEVERITY NVD IN BATCH
    # ==========================================================
    cve_ids = []
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve_id = vuln.get("VulnerabilityID")
            if cve_id and cve_id.startswith("CVE-"):
                cve_ids.append(cve_id.upper())

    cve_ids = list(set(cve_ids))
    nvd_cves = get_nvd_cves_batch(cve_ids)

    # ==========================================================
    # COSTRUZIONE MAPPA CVE -> SEVERITY
    # ==========================================================
    nvd_severities = {}

    for cve_id, cve in nvd_cves.items():
        metrics = cve.get("metrics", {})
        scores = []

        for version in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"]:
            for metric in metrics.get(version, []):
                if metric.get("source") == "nvd@nist.gov":
                    score = (
                        metric.get("cvssData", {}).get("baseScore")
                    )
                    if score is not None:
                        scores.append(score)

        if scores:
            score = max(scores)
            if score >= 9.0:
                severity = "CRITICAL"
            elif score >= 7.0:
                severity = "HIGH"
            elif score >= 4.0:
                severity = "MEDIUM"
            elif score > 0:
                severity = "LOW"
            else:
                severity = "NONE"

            nvd_severities[cve_id] = severity

    # ==========================================================
    # RAGGRUPPAMENTO E PULIZIA (Spostato nel Backend)
    # ==========================================================
    grouped_vulnerabilities = {}

    SEVERITY_ORDER = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0
    }

    for result in report.get("Results", []):
        target = result.get("Target", "")

        for vuln in result.get("Vulnerabilities", []):
            package = vuln.get("PkgName", "Unknown")
            purl = vuln.get("PkgIdentifier", {}).get("PURL", "")
            cve_id = vuln.get("VulnerabilityID", "")
            
            # Normalizziamo il PURL per evitare duplicati dovuti a ?type=jar
            base_purl = purl.split("?")[0] if purl else f"{package}_{vuln.get('InstalledVersion', '')}"

            # Classificazione dipendenza
            dep_type_raw = dependency_classification.get(base_purl, "unknown")
            dependency_type_it = {
                "direct": "Diretta",
                "transitive": "Transitiva",
                "transitive_unknown": "Transitiva non dichiarata",
                "unknown": "Sconosciuta"
            }.get(dep_type_raw, "Sconosciuta")

            # Assegnazione NVD Severity
            cve_upper = cve_id.upper() if cve_id else ""
            severity = nvd_severities.get(cve_upper, str(vuln.get("Severity", "UNKNOWN")).upper())

            fixed_version = vuln.get("FixedVersion", "")
            status = vuln.get("Status", "unknown")
            title = vuln.get("Title", "Nessuna descrizione disponibile")

            # Chiave univoca basata sul componente normalizzato
            key = base_purl

            if key not in grouped_vulnerabilities:
                grouped_vulnerabilities[key] = {
                    "Targets": [target] if target else [],
                    "Severity": severity,
                    "Pacchetto": package,
                    "Versione": vuln.get("InstalledVersion", ""),
                    "Numero CVE": 1,
                    "CVE": [cve_id] if cve_id else [],
                    "Motivo": [title],
                    "Status": [status],
                    "FixedVersion": [fixed_version],
                    "PURL": purl,
                    "DependencyType": dependency_type_it
                }
            else:
                component = grouped_vulnerabilities[key]

                # Aggiungiamo il target se unico
                if target and target not in component["Targets"]:
                    component["Targets"].append(target)

                # Evitiamo di duplicare la stessa CVE sullo stesso componente
                if cve_id and cve_id not in component["CVE"]:
                    component["Numero CVE"] += 1
                    component["CVE"].append(cve_id)
                    component["Motivo"].append(title)
                    component["Status"].append(status)
                    component["FixedVersion"].append(fixed_version)

                # Mantieni la severità più alta
                if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(component["Severity"], 0):
                    component["Severity"] = severity

    formatted_components = list(grouped_vulnerabilities.values())
    
    # ==========================================================
    # SALVATAGGIO COMPONENTI VULNERABILI RAGGRUPPATI
    # ==========================================================
    grouped_components_file = os.path.join(
        STORAGE_DIR, "grouped_vulnerabilities.json"
    )

    with open(grouped_components_file, "w", encoding="utf-8") as f:
        json.dump({
            "count": len(formatted_components),
            "components": formatted_components
        }, f, indent=4, ensure_ascii=False)

    print(
        f"[TRIVY] Componenti vulnerabili unici raggruppati: {len(formatted_components)}",
        flush=True,
    )
    print(
        f"[TRIVY] Componenti raggruppati salvati in: {grouped_components_file}",
        flush=True,
    )


    return {
        "status": "success",
        "sbom": final_sbom,
        "report": vulnerability_report,
        "data": report,
        "grouped_components": formatted_components 
    }

# ============================================================
# GENERAZIONE GRAFI PER TUTTI I FILE TROVATI NELLA CARTELLA STORAGE (manifests e dependencies)
# ============================================================

@router.get("/generate-graphs")
def generate_graphs():
    graphs = {}
    graphs.update(generate_graphs_for_folder(os.path.join(STORAGE_DIR, "manifests")))
    graphs.update(generate_graphs_for_folder(os.path.join(STORAGE_DIR, "dependencies")))
    graphs.update(generate_graphs_for_folder(os.path.join(STORAGE_DIR, "docker_sbom_steps")))
    graphs.update(generate_graphs_for_folder(STORAGE_DIR))  # Include anche eventuali file SBOM nella root
    memo = {}
    hierarchy_with_weights_merged = {}
    final_merged_sbom_graph = build_universal_hierarchy("final_merged_sbom.json", STORAGE_DIR)

    for purl in final_merged_sbom_graph:
        stats = get_dependency_weight(purl, final_merged_sbom_graph, memo, visited_global=set())
        hierarchy_with_weights_merged[purl] = {
            "dependencies": final_merged_sbom_graph[purl],
            "weight": stats[0],
            "overlap": stats[2]
        }

    return {"status": "success", "graphs": graphs, "hierarchy_with_weights_merged": hierarchy_with_weights_merged}

# ============================================================
# GENERAZIONE SBOM DOCKER REMOTA e ANALISI COMPARATIVA IMMEDIATA
# ============================================================

@router.post("/generate-docker-sbom")
def generate_docker_sbom(
    docker_target: str, 
    vuln_type: str = "os,library",
    repo_url: str = "",
    branch: str = "",
    image_source: str = "published_then_build",
    dockerfile_path: str = "",
    build_context: str = ".",
):
    
    os.makedirs(os.path.join(STORAGE_DIR, "manifests"), exist_ok=True)
    os.makedirs(os.path.join(STORAGE_DIR, "dependencies"), exist_ok=True)
    
    print(f"[BACKEND] Avvio pipeline Docker per l'immagine: {docker_target}", flush=True)
    
    if image_source not in ("published", "published_then_build", "build"):
        raise HTTPException(400, "image_source non valido (published, published_then_build, build).")
 
    # Impostazioni salvate da upload_sbom (repository, branch, percorso del Dockerfile)
    saved = {}
    config_path = os.path.join(STORAGE_DIR, "upload_config.txt")
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            saved = json.load(f)
 
    docker_inputs = {
        "src_vuln_type": vuln_type,
        "force_build": "true" if image_source == "build" else "false",
    }
 
    # Immagine pubblicata: non si manda con "build", cosi' non c'e' mai una riserva sbagliata
    if image_source in ("published", "published_then_build"):
        if not docker_target:
            raise HTTPException(400, "Indicare l'immagine pubblicata da analizzare.")
        docker_inputs["image_repository"] = docker_target
 
    # Build dal Dockerfile: serve il repository sorgente
    if image_source in ("published_then_build", "build"):
        repo = to_owner_repo(repo_url or saved.get("repo_url", ""))
        if not repo:
            raise HTTPException(400, "Repository sorgente mancante: impossibile costruire l'immagine dal Dockerfile.")
        docker_inputs.update({
            "src_repository": repo,
            "src_branch": branch or saved.get("branch") or "main",
            "dockerfile_path": dockerfile_path or saved.get("dockerfile_path") or "Dockerfile",
            "build_context": build_context or ".",
        })
    
    docker_action_info = trigger_github_action("sbom_dockerfile.yml", docker_inputs) 
    if not docker_action_info:
        raise HTTPException(500, "Impossibile avviare la pipeline Docker remota.")
        
    # Attesa completamento e download dello ZIP (estratto in STORAGE_DIR)
    success = wait_and_download_artifacts(docker_action_info["id"], STORAGE_DIR)
    if not success:
        raise HTTPException(500, "Pipeline completata ma nessun artifact trovato.")

    # Individuazione del file SBOM base generato da Trivy (cyclonedx-SBOM.json)
    base_sbom_name = "cyclonedx-SBOM.json"
    target_path = os.path.join(STORAGE_DIR, base_sbom_name)
    
    if not os.path.exists(target_path):
        # Fallback nel caso in cui i file siano dentro una sottocartella dello zip
        found = False
        for root, _, files in os.walk(STORAGE_DIR):
            if base_sbom_name in files:
                shutil.move(os.path.join(root, base_sbom_name), target_path)
                found = True
                break
        if not found:
            raise HTTPException(500, f"Artifact scaricato con successo, ma '{base_sbom_name}' non è stato trovato.")

    # Rinominiamo il file in standard 'docker_sbom.json' per i futuri controlli del backend
    shutil.move(target_path, os.path.join(STORAGE_DIR, "docker_sbom.json"))

    docker_sbom_path = os.path.join(STORAGE_DIR, "docker_sbom.json")

    # Costruisce il grafo iniziale usando le relazioni dei sorgenti.
    docker_graph_results = build_universal_hierarchy("docker_sbom.json", STORAGE_DIR)

    # Recupera eventuali archi mancanti tramite deps.dev.
    docker_graph_results, deps_dev_edges = complete_graph_with_deps_dev(
        docker_graph_results,
        docker_sbom_path
    )

    # Calcola i pesi soltanto dopo il completamento del grafo.
    memo = {}
    hierarchy_with_weights = {}

    for purl in docker_graph_results:
        stats = get_dependency_weight(
            purl,
            docker_graph_results,
            memo,
            visited_global=set()
        )

        hierarchy_with_weights[purl] = {
            "dependencies": docker_graph_results[purl],
            "weight": stats[0],
            "overlap": stats[2]
        }
    
    
    def get_global_code_map():
        #Restituisce: { purl: [ {file: 'nomefile.json', name: '...', version: '...'}, ... ] }
        global_map = {}
        target_dirs = [os.path.join(STORAGE_DIR, "manifests"), os.path.join(STORAGE_DIR, "dependencies"), os.path.join(STORAGE_DIR, "docker_sbom_steps")]
        ignore_files = {"docker_sbom.json", "cyclonedx-vuln-SBOM.json", "cyclonedx-license-SBOM.json"}
        
        for folder in target_dirs:
            if os.path.exists(folder):
                for root, _, files in os.walk(folder):
                    for file_name in files:
                        if file_name.endswith(".json") and file_name not in ignore_files:
                            if "vuln" in file_name or "license" in file_name:
                                continue  # Ignora file di vulnerabilità e licenze
                            else:
                                with open(os.path.join(root, file_name), "r", encoding="utf-8") as f:
                                    data = json.load(f)
                                    items = data.get("components", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                                    for c in items:
                                        if isinstance(c, dict) and c.get("purl"):
                                            purl = str(c["purl"]).lower().strip()
                                            if purl not in global_map: global_map[purl] = []
                                            global_map[purl].append({
                                                "source": file_name,
                                                "name": c.get("name"),
                                                "version": c.get("version")
                                            })
        return global_map
    
    # Recuperiamo la mappa globale dei componenti del codice per il confronto con lo SBOM Docker
    code_map = get_global_code_map() 
    all_code_purls = set(code_map.keys())
    
    # Carichiamo i componenti appena scaricati dal Docker
    docker_components = []
    try:
        with open(os.path.join(STORAGE_DIR, "docker_sbom.json"), "r", encoding="utf-8") as f:
            d_data = json.load(f)
        for c in d_data.get("components", []):
            if isinstance(c, dict):
                docker_components.append({
                    "name": c.get("name", "unknown"),
                    "version": c.get("version", "unknown"),
                    "purl": c.get("purl", "")
                })
    except Exception as e:
        raise HTTPException(500, f"Errore nel parsing del nuovo SBOM Docker: {str(e)}")

    in_common = []
    only_in_docker = []
    version_mismatches = []
    
    # Creiamo una mappa dei nomi dei pacchetti nel codice con le loro versioni per un confronto più accurato
    code_version_map = {}
    for p in all_code_purls:
        if "@" in p:
            parts = p.split("@")
            version = parts[-1]
            # Estraiamo il nome dal PURL (es. pkg:pypi/nome -> nome)
            name = parts[0].split("/")[-1].lower().strip()
            code_version_map[name] = version
    
    # Creiamo un set di tutti i nomi dei pacchetti nel codice per un confronto più semplice
    all_code_names_only = {entry["name"].lower().strip() for entries in code_map.values() for entry in entries if entry.get("name")}
    
    docker_components_unique = {f"{c['name'].lower().strip()}@{c['version']}": c for c in docker_components}.values()
    
    # CONFRONTO OTTIMIZZATO
    # Viene confrontato ogni componente Docker con la mappa globale dei componenti del codice, basandosi prima sul PURL (se disponibile)
    # e poi sul nome del pacchetto (per versioni diverse o assenti)
    for dc in docker_components_unique:
        dc_name_clean = dc["name"].lower().strip()
        dc_purl_clean = dc["purl"].lower().strip() if dc["purl"] else ""
        match_found = False
        matched_purl = None
        
        # se il PURL è disponibile, usiamolo per un confronto più preciso (inclusi versioni e parametri)
        if dc_purl_clean:
            if dc_purl_clean in all_code_purls:
                match_found = True
                matched_purl = dc_purl_clean
            else:
                for cp in all_code_purls:
                    if dc_purl_clean in cp or cp in dc_purl_clean:
                        match_found = True
                        matched_purl = cp
                        break
        
        
        if match_found:
            dc["source_files"] = code_map.get(matched_purl, [])
            in_common.append(dc)
        else:
            if dc_name_clean in all_code_names_only:
                source_details = []
                for entries in code_map.values():
                    for e in entries:
                        if e.get("name", "").lower().strip() == dc_name_clean:
                            source_details.append(e)
                
                version_mismatches.append({
                    "docker": dc,
                    "code_version": code_version_map.get(dc_name_clean, "Versione non trovata"),
                    "source_files": source_details
                })
            else:
                only_in_docker.append(dc)
                
    # Ordiniamo i risultati per nome in modo case-insensitive per una visualizzazione più ordinata nel frontend
    docker_components_unique = sorted(docker_components_unique, key=lambda x: x["name"].lower())
    in_common = sorted(in_common, key=lambda x: x["name"].lower())
    only_in_docker = sorted(only_in_docker, key=lambda x: x["name"].lower())
    version_mismatches = sorted(version_mismatches, key=lambda x: x["docker"]["name"].lower())
    
    
    # --- Analisi separata per le dipendenze che ci sono nel sorgente ma non nel docker SBOM ---
    
    removed_path = os.path.join(STORAGE_DIR, "removed_components.json")

    if os.path.exists(removed_path):
        with open(removed_path, "r", encoding="utf-8") as f:
            components_to_remove = json.load(f)
    else:
        components_to_remove = []
    
    docker_purl_set = {dc["purl"].lower().strip() for dc in docker_components if dc.get("purl")}
    removed_purl_set = { comp["purl"].lower().strip() for comp in components_to_remove if comp.get("purl")}
    missing_in_docker = []

    for purl, entries in code_map.items():
        
        normalized_purl = purl.lower().strip()

        # Ignora i componenti presenti nella lista di rimozione
        if normalized_purl in removed_purl_set:
            continue
        
        if normalized_purl not in docker_purl_set:
            missing_in_docker.append({
                "name": entries[0]["name"],
                "version": entries[0]["version"],
                "purl": purl,
                "files": list({e["source"] for e in entries})
            })
    
    docker_report = {
        "total_docker_packages": len(docker_components),
        "packages_in_common_count": len(in_common),
        "packages_only_in_docker_count": len(only_in_docker),
        "packages_with_version_mismatches_count": len(version_mismatches),
        "packages_missing_in_docker_count": len(missing_in_docker),
        "total_unique_docker_packages": len(docker_components_unique),
        "docker_components": docker_components,
        "in_common": in_common,
        "only_in_docker": only_in_docker,
        "version_mismatches": version_mismatches,
        "missing_in_docker": missing_in_docker
    }

    # Per il download button del Frontend, restituiamo anche lo SBOM Docker completo in formato testo (raw)
    raw_docker_sbom = ""
    try:
        with open(os.path.join(STORAGE_DIR, "docker_sbom.json"), "r", encoding="utf-8") as f:
            raw_docker_sbom = f.read()
    except Exception as e:
        print(f"[WARNING] Impossibile leggere lo SBOM grezzo: {str(e)}")
        
    analyzed_image = None
    try:
        for p in d_data.get("metadata", {}).get("component", {}).get("properties", []):
            if p.get("name") == "aquasecurity:trivy:Reference":
                analyzed_image = p.get("value")
    except Exception:
        pass
        
    return {
        "status": "success", 
        "github_run_url": docker_action_info["html_url"], 
        "message": "SBOM Docker generato, scaricato e confrontato con successo.",
        "docker_report": docker_report,
        "raw_docker_sbom": raw_docker_sbom,
        "graphs": docker_graph_results,
        "hierarchy_with_weights": hierarchy_with_weights,
        "deps_dev_edges": deps_dev_edges,
        "analyzed_image": analyzed_image
    }
    
    
# ============================================================
# RQ1 / RQ1.1: componenti aggiuntivi rispetto alla scansione classica
# ============================================================

IGNORED_TYPES = {"application", "file", "container", "operating-system"}  # nodi "contenitore", non componenti reali
 
 
# Ecosistemi in cui nomi/namespace sono case-insensitive
CASE_INSENSITIVE_TYPES = {"pypi", "npm", "deb", "apk", "rpm"}
 
 
def normalize_purl(purl: str) -> str:
    """Chiave di confronto stabile per purl di qualsiasi ecosistema."""
    if not purl:
        return ""
    p = unquote(purl.split("?")[0].split("#")[0].strip())
 
    m = re.match(r"pkg:([^/]+)/(.*)", p)
    if not m:
        return p.lower()
 
    ptype, rest = m.group(1).lower(), m.group(2)
 
    if ptype in CASE_INSENSITIVE_TYPES:
        rest = rest.lower()
 
    if ptype == "pypi":
        name, sep, ver = rest.partition("@")
        rest = re.sub(r"[-_.]+", "-", name) + sep + ver
 
    return f"pkg:{ptype}/{rest}"
 
 
def loose_key(purl: str):
    """(tipo, nome, versione senza epoch): confronto meno rigido, usato solo come ripiego."""
    k = normalize_purl(purl or "")
    m = re.match(r"^pkg:([^/]+)/(?:.*/)?([^/@]+)@(.*)$", k)
    if not m:
        return None
    ptype, name, version = m.groups()
    return (ptype, name, re.sub(r"^\d+:", "", version))
 
 
def component_key(c: dict) -> str:
    if c.get("purl"):
        return normalize_purl(c["purl"])
    # Senza purl: chiave di ripiego su nome@versione
    return f"nopurl:{str(c.get('name', '')).lower().strip()}@{c.get('version', '')}"
 
 
def load_components(file_paths: list) -> dict:
    """Ritorna {key: {name, version, purl, type, sources:set}} unendo i file SBOM CycloneDX."""
    result = {}
 
    def walk(items, source):
        for c in items or []:
            if not isinstance(c, dict):
                continue
            if c.get("type") not in IGNORED_TYPES and (c.get("purl") or c.get("name")):
                key = component_key(c)
                entry = result.setdefault(key, {
                    "name": c.get("name"),
                    "version": c.get("version"),
                    "purl": c.get("purl"),
                    "type": c.get("type"),
                    "raw": c,  # componente originale (con properties), serve per la scansione
                    "sources": set(),
                })
                entry["sources"].add(source)
            walk(c.get("components"), source)  # componenti annidati
 
    for path in file_paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[WARNING] SBOM non leggibile {path}: {e}", flush=True)
            continue
        walk(data.get("components") if isinstance(data, dict) else data, os.path.basename(path))
    return result
 
 
def scan_component(v: dict) -> dict:
    """
    Componente da passare a Trivy: parte dall'originale dello SBOM (properties incluse,
    es. aquasecurity:trivy:SrcName/SrcVersion usati per i pacchetti OS) e normalizza solo i campi chiave.
    """
    comp = dict(v.get("raw") or {})
    comp.pop("components", None)  # figli annidati: non servono
    if comp.get("type") in (None, *IGNORED_TYPES):
        comp["type"] = "library"
    comp["bom-ref"] = v["purl"]
    comp["name"] = v["name"]
    comp["version"] = v["version"]
    comp["purl"] = v["purl"]
    return comp
 
 
def ecosystem_of(c: dict) -> str:
    purl = c.get("purl") or ""
    m = re.match(r"pkg:([^/]+)/", purl)
    return m.group(1) if m else "no-purl"
 
 
OS_PKG_TYPES = {"deb", "apk", "rpm"}
 
 
def os_family_matches(pkg_type: str, os_name: str) -> bool:
    """Il componente operating-system è compatibile col tipo di pacchetto?"""
    name = (os_name or "").lower()
    if pkg_type == "deb":
        return name in {"debian", "ubuntu"}
    if pkg_type == "apk":
        return name == "alpine"
    if pkg_type == "rpm":
        return bool(name) and name not in {"debian", "ubuntu", "alpine"}
    return False
 
 
def find_os_component(pkg_type, source_names, steps_files, docker_sbom_file, cache):
    """
    Cerca il componente operating-system compatibile: prima negli SBOM da cui
    provengono i pacchetti, poi nell'SBOM dell'immagine finale.
    """
    paths = [p for p in steps_files if os.path.basename(p) in source_names] + [docker_sbom_file]
    for path in paths:
        if path not in cache:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                cache[path] = [c for c in data.get("components", []) if c.get("type") == "operating-system"]
            except Exception:
                cache[path] = []
        for c in cache[path]:
            if os_family_matches(pkg_type, c.get("name")):
                return c
    return None


def loose_key_to_key(purl: str, components: dict):
    """Trova la chiave del componente usando il confronto meno rigido,
    solo quando la corrispondenza è univoca."""
    lk = loose_key(purl)
    if lk is None:
        return None

    matches = [
        k for k, v in components.items()
        if loose_key(v.get("purl", "")) == lk
    ]

    return matches[0] if len(matches) == 1 else None

 
@router.get("/additional-components-analysis")
def additional_components_analysis(include_removed: bool = False):
    manifests_files = glb.glob(os.path.join(STORAGE_DIR, "manifests", "*.json"))
    docker_sbom_file = os.path.join(STORAGE_DIR, "docker_sbom.json")
    steps_files = glb.glob(os.path.join(STORAGE_DIR, "docker_sbom_steps", "*.json"))
 
    if not os.path.exists(docker_sbom_file):
        raise HTTPException(404, "docker_sbom.json non trovato. Generare prima lo SBOM Docker.")
    if not manifests_files:
        raise HTTPException(404, "Nessun SBOM da sorgente trovato in manifests/.")
    if not steps_files:
        raise HTTPException(404, "Nessun SBOM degli step Dockerfile trovato in docker_sbom_steps/.")
 
    # ---------- insiemi ----------
    source_components = load_components(manifests_files)
    image_components = load_components([docker_sbom_file])
    step_components = load_components(steps_files)
 
    # Baseline = sorgente U immagine finale
    baseline = dict(source_components)
    for k, v in image_components.items():
        if k in baseline:
            baseline[k]["sources"] |= v["sources"]
        else:
            baseline[k] = v
 
    # Componenti rimossi dal Dockerfile
    removed_path = os.path.join(STORAGE_DIR, "removed_components.json")
    removed_keys = set()
    if os.path.exists(removed_path):
        with open(removed_path, "r", encoding="utf-8") as f:
            for c in json.load(f):
                if c.get("purl"):
                    removed_keys.add(normalize_purl(c["purl"]))
 
    additional_all = {k: v for k, v in step_components.items() if k not in baseline}
 
    # Flag: escludi i rimossi dagli aggiuntivi se non richiesto
    removed_in_additional = {k for k in additional_all if k in removed_keys}
    if include_removed:
        additional = additional_all
    else:
        additional = {k: v for k, v in additional_all.items() if k not in removed_keys}
 
    methodology_count = len(baseline) + len(additional)
 
    # ---------- RQ1: conteggi ----------
    with_version = {k: v for k, v in additional.items() if v.get("version")}
    without_version = {k: v for k, v in additional.items() if not v.get("version")}
    with_purl = {k: v for k, v in additional.items() if v.get("purl") and v.get("version")}
 
    by_ecosystem = defaultdict(int)
    for v in additional.values():
        by_ecosystem[ecosystem_of(v)] += 1
 
    rq1 = {
        "include_removed": include_removed,
        "source_components": len(source_components),
        "image_components": len(image_components),
        "baseline_components": len(baseline),
        "methodology_components": methodology_count,
        "additional_components": len(additional),
        "pct_additional_vs_methodology": round(len(additional) / methodology_count * 100, 2) if methodology_count > 0 else 0,
        "additional_with_version": len(with_version),
        "additional_without_version": len(without_version),
        "removed_in_dockerfile_total": len(removed_in_additional),
        "removed_excluded_from_analysis": 0 if include_removed else len(removed_in_additional),
        "additional_by_ecosystem": dict(by_ecosystem),
    }
 
    # ---------- RQ1.1: scansione vulnerabilità dei soli aggiuntivi ----------
    scannable = with_purl  # senza purl+versione Trivy non può associare CVE
    vulnerable = {}
    severity_count = defaultdict(int)
    unique_cves = set()
    scanned_keys = set()      # riconosciuti da Trivy (o gruppo scansionato quando non si puo' sapere)
    ignored_keys = set()      # in uno SBOM scansionato ma non riconosciuti da Trivy
    scan_errors = []
    scanned_by_group = {}
    unmatched_keys = set()    # vulnerabilita' di Trivy non riconducibili a un componente aggiuntivo
    recognition_unavailable = []
 
    # Stato di ogni componente aggiuntivo (per spiegare perche' non e' stato scansionato)
    scan_status = {}
    for k, v in additional.items():
        if not v.get("purl"):
            scan_status[k] = "non scansionabile: senza purl"
        elif not v.get("version"):
            scan_status[k] = "non scansionabile: senza versione"
 
    suffix = "with_removed" if include_removed else "without_removed"
    SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
 
    # Indice meno rigido (tipo, nome, versione senza epoch), solo per i casi non ambigui
    loose_index, ambiguous = {}, set()
    for k, v in scannable.items():
        lk = loose_key(v["purl"])
        if lk is None:
            continue
        if lk in loose_index:
            ambiguous.add(lk)
        loose_index[lk] = k
    for lk in ambiguous:
        loose_index.pop(lk, None)
 
    # Trivy non accetta uno SBOM con più tipi di pacchetti OS (es. deb + apk):
    # si scansiona uno SBOM per gruppo (librerie, deb, apk, rpm)
    groups = defaultdict(dict)
    for k, v in scannable.items():
        ptype = ecosystem_of(v).lower()
        groups[ptype if ptype in OS_PKG_TYPES else "library"][k] = v
 
    trivy_exe = get_trivy_path()
    if groups and not os.path.exists(trivy_exe):
        raise HTTPException(500, "Trivy non trovato.")
 
    os_cache = {}
 
    for group_name, group in groups.items():
        components = [scan_component(v) for v in group.values()]
 
        # I pacchetti OS richiedono il componente operating-system corrispondente
        if group_name in OS_PKG_TYPES:
            source_names = {s for v in group.values() for s in v["sources"]}
            os_component = find_os_component(group_name, source_names, steps_files, docker_sbom_file, os_cache)
            if os_component is None:
                scan_errors.append({
                    "group": group_name,
                    "components": len(group),
                    "error": "Componente operating-system compatibile non trovato negli SBOM.",
                })
                for k in group:
                    scan_status[k] = f"gruppo '{group_name}' non scansionato: OS non trovato"
                continue
            components.append(os_component)
 
        additional_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": components,
        }
 
        additional_sbom_path = os.path.join(STORAGE_DIR, f"additional_components_sbom_{suffix}_{group_name}.json")
        report_path = os.path.join(STORAGE_DIR, f"trivy_additional_vulnerabilities_{suffix}_{group_name}.json")
 
        with open(additional_sbom_path, "w", encoding="utf-8") as f:
            json.dump(additional_sbom, f, indent=2, ensure_ascii=False)
 
        try:
            subprocess.run(
                [trivy_exe, "sbom", "--list-all-pkgs", "--format", "json", "--output", report_path, additional_sbom_path],
                check=True, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            scan_errors.append({
                "group": group_name,
                "components": len(group),
                "error": (e.stderr or str(e))[-600:],
            })
            for k in group:
                scan_status[k] = f"gruppo '{group_name}' non scansionato: errore Trivy"
            continue
 
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
 
        # Pacchetti che Trivy ha davvero riconosciuto (con --list-all-pkgs)
        recognized, recognized_loose, has_packages = set(), set(), False
        for res in report.get("Results", []):
            for pkg in res.get("Packages") or []:
                has_packages = True
                p = (pkg.get("Identifier") or {}).get("PURL")
                if p:
                    recognized.add(normalize_purl(p))
                    lk = loose_key(p)
                    if lk:
                        recognized_loose.add(lk)
 
        if not has_packages:
            recognition_unavailable.append(group_name)  # non si puo' sapere: si considerano scansionati
 
        for k, v in group.items():
            if not has_packages or k in recognized or loose_key(v["purl"]) in recognized_loose:
                scanned_keys.add(k)
                scan_status[k] = "scansionato"
            else:
                ignored_keys.add(k)
                scan_status[k] = "non riconosciuto da Trivy (tipo di pacchetto non supportato?)"
 
        scanned_by_group[group_name] = sum(1 for k in group if k in scanned_keys)
 
        for res in report.get("Results", []):
            for vuln in res.get("Vulnerabilities") or []:
                purl = vuln.get("PkgIdentifier", {}).get("PURL", "")
                key = normalize_purl(purl) if purl else None
                if key not in additional:
                    key = loose_index.get(loose_key(purl)) if purl else None  # confronto meno rigido
                if key not in additional:
                    unmatched_keys.add(normalize_purl(purl) if purl else "(senza purl)")
                    continue
                sev = str(vuln.get("Severity", "UNKNOWN")).upper()
                cve = vuln.get("VulnerabilityID")
                entry = vulnerable.setdefault(key, {
                    "name": additional[key]["name"],
                    "version": additional[key]["version"],
                    "purl": additional[key]["purl"],
                    "sources": sorted(additional[key]["sources"]),
                    "cves": set(),
                    "max_severity": "UNKNOWN",
                })
                entry["cves"].add(cve)
                unique_cves.add(cve)
                if SEV_ORDER.get(sev, 0) > SEV_ORDER.get(entry["max_severity"], 0):
                    entry["max_severity"] = sev
 
    for v in vulnerable.values():
        severity_count[v["max_severity"]] += 1
        v["cves"] = sorted(v["cves"])
        v["cve_count"] = len(v["cves"])
 
    # ---------- controllo incrociato con la scansione dello SBOM unito (se disponibile) ----------
    crosscheck = None
    grouped_path = os.path.join(STORAGE_DIR, "grouped_vulnerabilities.json")
    if os.path.exists(grouped_path):
        try:
            with open(grouped_path, "r", encoding="utf-8") as f:
                grouped = json.load(f).get("components", [])
            merged_keys = {normalize_purl(c.get("PURL")) for c in grouped if c.get("PURL")}
            merged_loose = {loose_key(c.get("PURL")) for c in grouped if c.get("PURL")}
            vulnerable_in_merged = [
                k for k, v in additional.items()
                if k in merged_keys or (v.get("purl") and loose_key(v["purl"]) in merged_loose)
            ]
            missed = [k for k in vulnerable_in_merged if k not in vulnerable]
            crosscheck = {
                "additional_vulnerable_in_merged_scan": len(vulnerable_in_merged),
                "missed_by_rq1_1_count": len(missed),
                "missed_by_rq1_1": [
                    {
                        "name": additional[k]["name"],
                        "version": additional[k]["version"],
                        "purl": additional[k]["purl"],
                        "scan_status": scan_status.get(k),
                    }
                    for k in missed[:50]
                ],
            }
        except Exception as e:
            print(f"[WARNING] Controllo incrociato non riuscito: {e}", flush=True)
 
    # ---------- contabilità: ogni componente aggiuntivo in una sola voce ----------
    n_without_purl = sum(1 for v in additional.values() if not v.get("purl"))
    n_without_version = sum(1 for v in additional.values() if v.get("purl") and not v.get("version"))
    n_group_failed = len(scannable) - len(scanned_keys) - len(ignored_keys)
    accounted = len(scanned_keys) + len(ignored_keys) + n_without_purl + n_without_version + n_group_failed
 
    rq1_1 = {
        "scanned_components": len(scanned_keys),
        "not_scannable_components": len(additional) - len(scanned_keys),
        "not_scannable_no_purl_or_version": len(additional) - len(scannable),
        "scan_failed_components": len(scannable) - len(scanned_keys),
        "scanned_by_group": scanned_by_group,
        "scan_errors": scan_errors,
        "accounting": {
            "additional_total": len(additional),
            "scanned": len(scanned_keys),
            "without_purl": n_without_purl,
            "without_version": n_without_version,
            "group_failed": n_group_failed,
            "ignored_by_trivy": len(ignored_keys),
            "unaccounted": len(additional) - accounted,
            "recognition_unavailable_groups": recognition_unavailable,
        },
        "crosscheck_merged_scan": crosscheck,
        "trivy_unmatched_count": len(unmatched_keys),
        "trivy_unmatched_examples": sorted(unmatched_keys)[:10],
        "vulnerable_additional_components": len(vulnerable),
        "vulnerable_pct_of_additional": round(len(vulnerable) / len(additional) * 100, 2) if additional else 0,
        "vulnerable_pct_of_scanned": round(len(vulnerable) / len(scanned_keys) * 100, 2) if scanned_keys else 0,
        "unique_cves": len(unique_cves),
        "by_max_severity": dict(severity_count),
    }
 
    # ---------- salvataggio ----------
    output = {
        "rq1": rq1,
        "rq1_1": rq1_1,
        "additional_components": [
            {
                **{k2: v2 for k2, v2 in c.items() if k2 not in ("sources", "raw")},
                "sources": sorted(c["sources"]),
                "key": k,
                "scan_status": scan_status.get(k),
            }
            for k, c in additional.items()
        ],
        "vulnerable_additional_components": list(vulnerable.values()),
    }
    with open(os.path.join(STORAGE_DIR, f"rq1_results_{suffix}.json"), "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)
 
    return {"status": "success", **output}

# ============================================================
# RQ1.1: CONFRONTO SBOM SORGENTE vs IMMAGINE FINALE
# ============================================================

@router.get("/compare-source-image-sboms")
def compare_source_image_sboms():
    manifests_files = sorted(
        glb.glob(os.path.join(STORAGE_DIR, "manifests", "*.json"))
    )

    docker_sbom_file = os.path.join(STORAGE_DIR, "docker_sbom.json")
    steps_files = sorted(
        glb.glob(os.path.join(STORAGE_DIR, "docker_sbom_steps", "*.json"))
    )

    if not manifests_files:
        raise HTTPException(
            404,
            "Nessuno SBOM del sorgente trovato in manifests/."
        )

    if not os.path.exists(docker_sbom_file):
        raise HTTPException(
            404,
            "docker_sbom.json non trovato. Generare prima lo SBOM dell'immagine."
        )

    # Caricamento e unione dei componenti dei due contesti
    source_components = load_components(manifests_files)
    image_components = load_components([docker_sbom_file])

    # Le chiavi usano PURL normalizzati; se manca il PURL viene usato
    # il ripiego nome@versione previsto da component_key().
    source_keys = set(source_components)
    image_keys = set(image_components)

    source_only = {
        k: v for k, v in source_components.items()
        if k not in image_keys
    }

    image_only = {
        k: v for k, v in image_components.items()
        if k not in source_keys
    }

    common = {
        k: v for k, v in source_components.items()
        if k in image_keys
    }

    # Per i componenti comuni manteniamo una sola voce, ma registriamo
    # esplicitamente che il componente è stato rilevato in entrambi i contesti.
    for k, component in common.items():
        component["sources"] = (
            set(source_components[k]["sources"])
            | set(image_components[k]["sources"])
        )

    categories = {
        "source_only": source_only,
        "image_only": image_only,
        "common": common,
    }

    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0,
    }

    trivy_exe = get_trivy_path()
    if not os.path.exists(trivy_exe):
        raise HTTPException(500, "Trivy non trovato.")

    # Cache dei componenti OS per le scansioni dei pacchetti di sistema.
    os_cache = {}

    def scan_category(category_name, components_map):
        """
        Scansiona i componenti di una categoria con Trivy SBOM.
        Ogni gruppo di pacchetti OS viene scansionato separatamente.
        """
        result_components = {}

        for key, component in components_map.items():
            result_components[key] = {
                "key": key,
                "name": component.get("name"),
                "version": component.get("version"),
                "purl": component.get("purl"),
                "type": component.get("type"),
                "sources": sorted(component.get("sources", set())),
                "vulnerabilities": [],
                "vulnerability_count": 0,
                "max_severity": "UNKNOWN",
                "scan_status": "non scansionato",
            }

            if not component.get("purl"):
                result_components[key]["scan_status"] = "non scansionabile: PURL mancante"
            elif not component.get("version"):
                result_components[key]["scan_status"] = "non scansionabile: versione mancante"

        # Trivy ha bisogno almeno di PURL e versione per associare
        # in modo affidabile le vulnerabilità ai componenti.
        scannable = {
            k: v for k, v in components_map.items()
            if v.get("purl") and v.get("version")
        }

        groups = defaultdict(dict)
        for key, component in scannable.items():
            ecosystem = ecosystem_of(component).lower()
            group_name = (
                ecosystem if ecosystem in OS_PKG_TYPES else "library"
            )
            groups[group_name][key] = component

        # Indice meno rigido per gestire PURL con differenze di formato,
        # solo se la combinazione tipo/nome/versione è univoca.
        loose_index = {}
        ambiguous = set()

        for key, component in scannable.items():
            lk = loose_key(component.get("purl"))
            if lk is None:
                continue
            if lk in loose_index:
                ambiguous.add(lk)
            else:
                loose_index[lk] = key

        for lk in ambiguous:
            loose_index.pop(lk, None)

        for group_name, group in groups.items():
            sbom_components = [
                scan_component(component)
                for component in group.values()
            ]

            # I pacchetti Debian/APK/RPM richiedono il componente OS
            # compatibile, altrimenti Trivy può non interpretarli correttamente.
            if group_name in OS_PKG_TYPES:
                source_names = {
                    source
                    for component in group.values()
                    for source in component.get("sources", set())
                }

                os_component = find_os_component(
                    group_name,
                    source_names,
                    steps_files,
                    docker_sbom_file,
                    os_cache,
                )

                if os_component is None:
                    for key in group:
                        result_components[key]["scan_status"] = (
                            f"non scansionato: OS compatibile "
                            f"non trovato per {group_name}"
                        )
                    continue

                sbom_components.append(os_component)

            sbom_data = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "components": sbom_components,
            }

            # File distinti per categoria e gruppo, per evitare
            # sovrascritture tra scansioni.
            safe_category = re.sub(r"[^a-zA-Z0-9_-]", "_", category_name)
            safe_group = re.sub(r"[^a-zA-Z0-9_-]", "_", group_name)

            sbom_path = os.path.join(
                STORAGE_DIR,
                f"rq1_{safe_category}_{safe_group}.json",
            )
            report_path = os.path.join(
                STORAGE_DIR,
                f"rq1_vulnerabilities_{safe_category}_{safe_group}.json",
            )

            with open(sbom_path, "w", encoding="utf-8") as f:
                json.dump(sbom_data, f, indent=2, ensure_ascii=False)

            try:
                subprocess.run(
                    [
                        trivy_exe,
                        "sbom",
                        "--list-all-pkgs",
                        "--format", "json",
                        "--output", report_path,
                        sbom_path,
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as e:
                error_message = (e.stderr or str(e))[-600:]
                for key in group:
                    result_components[key]["scan_status"] = (
                        f"errore durante la scansione Trivy: {error_message}"
                    )
                continue

            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)

            # Segniamo come scansionati i componenti passati a Trivy.
            for key in group:
                result_components[key]["scan_status"] = "scansionato"

            for res in report.get("Results", []):
                for vuln in res.get("Vulnerabilities") or []:
                    vuln_purl = (
                        vuln.get("PkgIdentifier", {}).get("PURL", "")
                    )

                    matched_key = (
                        normalize_purl(vuln_purl) if vuln_purl else None
                    )

                    if matched_key not in group:
                        matched_key = (
                            loose_index.get(loose_key(vuln_purl))
                            if vuln_purl else None
                        )

                    # Evita di attribuire una CVE al componente sbagliato
                    # quando Trivy non fornisce un identificatore riconoscibile.
                    if matched_key not in group:
                        continue

                    severity = str(
                        vuln.get("Severity") or "UNKNOWN"
                    ).upper()

                    result_vulnerability = {
                        "id": vuln.get("VulnerabilityID") or "N/A",
                        "severity": severity,
                        "title": vuln.get("Title") or "",
                        "installed_version": vuln.get("InstalledVersion") or "",
                        "fixed_version": vuln.get("FixedVersion") or "",
                        "primary_url": vuln.get("PrimaryURL") or "",
                    }

                    entry = result_components[matched_key]
                    # Evita doppioni della stessa CVE sul medesimo componente.
                    if not any(
                        existing["id"] == result_vulnerability["id"]
                        for existing in entry["vulnerabilities"]
                    ):
                        entry["vulnerabilities"].append(result_vulnerability)

                    if severity_order.get(severity, 0) > severity_order.get(
                        entry["max_severity"], 0
                    ):
                        entry["max_severity"] = severity

        for entry in result_components.values():
            entry["vulnerabilities"].sort(
                key=lambda v: (
                    -severity_order.get(v["severity"], 0),
                    v["id"],
                )
            )
            entry["vulnerability_count"] = len(entry["vulnerabilities"])

        vulnerable_count = sum(
            1 for entry in result_components.values()
            if entry["vulnerability_count"] > 0
        )

        severity_counts = defaultdict(int)

        for entry in result_components.values():
            if entry["vulnerability_count"] > 0:
                severity = entry["max_severity"] or "UNKNOWN"
                severity_counts[severity] += 1

        return {
            "total_components": len(result_components),
            "vulnerable_components": vulnerable_count,
            "components_with_vulnerabilities_pct": round(
                vulnerable_count / len(result_components) * 100, 2
            ) if result_components else 0,
            "severity_counts": dict(severity_counts),
            "components": sorted(
                result_components.values(),
                key=lambda c: (
                    c["name"] or "",
                    c["version"] or "",
                ),
            ),
        }

    results = {
        category_name: scan_category(category_name, component_map)
        for category_name, component_map in categories.items()
    }

    return {
        "status": "success",
        "summary": {
            "source_components": len(source_components),
            "image_components": len(image_components),
            "source_only": len(source_only),
            "image_only": len(image_only),
            "common": len(common),
        },
        "categories": results,
    }

# ============================================================
# RQ1.2: componenti dell'immagine finale presenti negli step Dockerfile ma assenti dallo SBOM del sorgente 
# + vulnerabilità
# ============================================================

@router.get("/image-components-from-dockerfile")
def image_components_from_dockerfile():
    manifests_files = glb.glob(
        os.path.join(STORAGE_DIR, "manifests", "*.json")
    )
    docker_sbom_file = os.path.join(STORAGE_DIR, "docker_sbom.json")
    steps_files = glb.glob(
        os.path.join(STORAGE_DIR, "docker_sbom_steps", "*.json")
    )

    if not os.path.exists(docker_sbom_file):
        raise HTTPException(
            404, "docker_sbom.json non trovato."
        )
    if not manifests_files:
        raise HTTPException(
            404, "Nessuno SBOM del sorgente trovato."
        )
    if not steps_files:
        raise HTTPException(
            404, "Nessuno SBOM degli step Dockerfile trovato."
        )

    # ---------- Caricamento SBOM ----------
    source_components = load_components(manifests_files)
    image_components = load_components([docker_sbom_file])
    step_components = load_components(steps_files)

    # ---------- Selezione dei componenti ----------
    # Presenti nell'immagine finale
    # + presenti negli step Dockerfile
    # - presenti nello SBOM del sorgente

    selected = {}

    for k, image_component in image_components.items():
        if k not in step_components:
            continue

        if k in source_components:
            continue

        component = dict(image_component)
        component["sources"] = (
            image_component["sources"]
            | step_components[k]["sources"]
        )

        selected[k] = component

    # ---------- Preparazione scansione vulnerabilità ----------
    scannable = {
        k: v for k, v in selected.items()
        if v.get("purl") and v.get("version")
    }

    scan_status = {}

    for k, v in selected.items():
        if not v.get("purl"):
            scan_status[k] = "non scansionabile: senza purl"
        elif not v.get("version"):
            scan_status[k] = "non scansionabile: senza versione"

    groups = defaultdict(dict)

    for k, v in scannable.items():
        ptype = ecosystem_of(v).lower()
        group_name = (
            ptype if ptype in OS_PKG_TYPES else "library"
        )
        groups[group_name][k] = v

    vulnerable = {}
    scan_errors = []
    scanned_keys = set()
    ignored_keys = set()
    os_cache = {}

    SEV_ORDER = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0,
    }

    trivy_exe = get_trivy_path()

    if groups and not os.path.exists(trivy_exe):
        raise HTTPException(500, "Trivy non trovato.")

    for group_name, group in groups.items():
        components = [
            scan_component(v) for v in group.values()
        ]

        # I pacchetti OS richiedono il componente OS
        # compatibile, come nella route RQ1 esistente.
        if group_name in OS_PKG_TYPES:
            source_names = {
                source
                for v in group.values()
                for source in v["sources"]
            }

            os_component = find_os_component(
                group_name,
                source_names,
                steps_files,
                docker_sbom_file,
                os_cache,
            )

            if os_component is None:
                scan_errors.append({
                    "group": group_name,
                    "components": len(group),
                    "error": (
                        "Componente operating-system "
                        "compatibile non trovato."
                    ),
                })

                for k in group:
                    scan_status[k] = (
                        f"non scansionato: OS "
                        f"compatibile non trovato ({group_name})"
                    )
                continue

            components.append(os_component)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": components,
        }

        sbom_path = os.path.join(
            STORAGE_DIR,
            f"rq1_2_sbom_{group_name}.json",
        )
        report_path = os.path.join(
            STORAGE_DIR,
            f"rq1_2_vulnerabilities_{group_name}.json",
        )

        with open(sbom_path, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2, ensure_ascii=False)

        try:
            subprocess.run(
                [
                    trivy_exe,
                    "sbom",
                    "--list-all-pkgs",
                    "--format", "json",
                    "--output", report_path,
                    sbom_path,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            scan_errors.append({
                "group": group_name,
                "components": len(group),
                "error": (e.stderr or str(e))[-600:],
            })

            for k in group:
                scan_status[k] = "errore durante la scansione Trivy"
            continue

        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        # Riconoscimento dei pacchetti da parte di Trivy
        recognized = set()
        recognized_loose = set()
        has_packages = False

        for res in report.get("Results", []):
            for pkg in res.get("Packages") or []:
                has_packages = True
                purl = (
                    (pkg.get("Identifier") or {}).get("PURL")
                )

                if purl:
                    recognized.add(normalize_purl(purl))
                    lk = loose_key(purl)
                    if lk:
                        recognized_loose.add(lk)

        for k, v in group.items():
            if (
                not has_packages
                or k in recognized
                or loose_key(v["purl"]) in recognized_loose
            ):
                scanned_keys.add(k)
                scan_status[k] = "scansionato"
            else:
                ignored_keys.add(k)
                scan_status[k] = (
                    "non riconosciuto da Trivy"
                )

        # ---------- Raccolta vulnerabilità ----------
        for res in report.get("Results", []):
            for vuln in res.get("Vulnerabilities") or []:
                purl = (
                    vuln.get("PkgIdentifier", {}).get("PURL", "")
                )
                key = normalize_purl(purl) if purl else None

                if key not in group:
                    key = (
                        loose_key_to_key(purl, group)
                        if purl else None
                    )

                if key not in group:
                    continue

                severity = str(
                    vuln.get("Severity", "UNKNOWN")
                ).upper()
                cve = vuln.get("VulnerabilityID")

                entry = vulnerable.setdefault(key, {
                    "name": selected[key]["name"],
                    "version": selected[key]["version"],
                    "purl": selected[key]["purl"],
                    "sources": sorted(selected[key]["sources"]),
                    "cves": set(),
                    "max_severity": "UNKNOWN",
                })

                if cve:
                    entry["cves"].add(cve)

                if SEV_ORDER.get(severity, 0) > SEV_ORDER.get(
                    entry["max_severity"], 0
                ):
                    entry["max_severity"] = severity

    # ---------- Formattazione risultati ----------
    severity_count = defaultdict(int)

    for v in vulnerable.values():
        severity_count[v["max_severity"]] += 1
        v["cves"] = sorted(v["cves"])
        v["cve_count"] = len(v["cves"])

    for k, v in selected.items():
        v["sources"] = sorted(v["sources"])

    return {
        "status": "success",
        "rq1_2": {
            "source_components": len(source_components),
            "image_components": len(image_components),
            "dockerfile_step_components": len(step_components),
            "selected_components": len(selected),
            "scannable_components": len(scannable),
            "scanned_components": len(scanned_keys),
            "not_recognized_by_trivy": len(ignored_keys),
            "scan_errors": scan_errors,
            "vulnerable_components": len(vulnerable),
            "vulnerable_pct_of_selected": round(
                len(vulnerable) / len(selected) * 100, 2
            ) if selected else 0,
            "unique_cves": len({
                cve
                for v in vulnerable.values()
                for cve in v["cves"]
            }),
            "by_max_severity": dict(severity_count),
        },
        "selected_components": [
            {
                **v,
                "key": k,
                "scan_status": scan_status.get(k),
            }
            for k, v in selected.items()
        ],
        "vulnerable_components": list(vulnerable.values()),
    }

# ============================================================
# RQ2 / 2.1 / 2.2 / 2.3: valore della caratterizzazione dei componenti
# ============================================================

RQ2_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
RQ2_CATEGORIES = ["declared", "transitive", "unknown", "transitive_unknown", "unmapped"]
RQ2_LABELS = {
    "declared": "Dichiarato",
    "transitive": "Transitivo",
    "unknown": "Sconosciuto diretto",
    "transitive_unknown": "Sconosciuto transitivo",
    "unmapped": "Non mappato",  # vulnerabile ma assente dall'analisi di caratterizzazione
}
RQ2_TARGET = {"declared", "unknown"}  # dichiarati + sconosciuti diretti
RQ2_SOURCE_FILES = ["requirements.txt", "pyproject.toml", "pom.xml", "build.gradle", "build.gradle.kts"]


def pct(n, d):
    return round(n / d * 100, 2) if d else 0


def build_classification_map(analysis: dict) -> dict:
    """{purl normalizzato: declared | transitive | unknown | transitive_unknown}"""
    mapping = {}
    if analysis.get("status") != "success":
        return mapping
    for c in analysis.get("not_declared", []):
        if c.get("purl"):
            mapping[normalize_purl(c["purl"])] = c.get("classification", "unknown")
    for c in analysis.get("declared", []):
        if c.get("purl"):
            mapping[normalize_purl(c["purl"])] = "declared"
    return mapping


def classic_classification_map():
    """
    Applica la STESSA caratterizzazione allo SBOM della metodologia classica
    (manifests + immagine Docker finale, senza gli step del Dockerfile).
    Ritorna (mappa, errore).
    """
    classic_dir = os.path.join(STORAGE_DIR, "rq_results", "classic_characterization")
    shutil.rmtree(classic_dir, onerror=remove_readonly, ignore_errors=True)
    os.makedirs(classic_dir, exist_ok=True)

    # I file sorgente servono a load_source_dependencies (cerca nella cartella passata)
    for pattern in ["*requirements*.txt", "*pyproject.toml", "*pom.xml", "*build.gradle", "*build.gradle.kts"]:
        for src in glb.glob(os.path.join(STORAGE_DIR, pattern)):
            shutil.copy(src, os.path.join(classic_dir, os.path.basename(src)))
    
    files = glb.glob(os.path.join(STORAGE_DIR, "manifests", "*.json"))
    docker_sbom_file = os.path.join(STORAGE_DIR, "docker_sbom.json")
    if os.path.exists(docker_sbom_file):
        files.append(docker_sbom_file)
    if not files:
        return None, "Nessun SBOM classico (manifests / docker_sbom.json) trovato."

    cyclonedx_exe = get_cyclonedx_path()
    if not os.path.exists(cyclonedx_exe):
        return None, "Tool CycloneDX CLI non trovato."

    out_file = os.path.join(classic_dir, "final_merged_sbom.json")
    try:
        subprocess.run(
            [cyclonedx_exe, "merge", "--input-files"] + files + ["--output-file", out_file],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        return None, f"Merge classico fallito: {e.stderr or e}"

    analysis = analyze_source_components(classic_dir)
    if analysis.get("status") != "success":
        return None, analysis.get("message", "Caratterizzazione classica fallita.")

    return build_classification_map(analysis), None


@router.get("/characterization-analysis")
def characterization_analysis():

    # ========================================================
    # MERGE: MANIFEST + IMMAGINE DOCKER FINALE
    # ========================================================

    manifests_files = sorted(
        glb.glob(os.path.join(STORAGE_DIR, "manifests", "*.json"))
    )

    docker_sbom_file = os.path.join(STORAGE_DIR, "docker_sbom.json")

    if not manifests_files:
        raise HTTPException(
            404,
            "Nessuno SBOM del sorgente trovato in manifests/."
        )

    if not os.path.exists(docker_sbom_file):
        raise HTTPException(
            404,
            "docker_sbom.json non trovato."
        )

    cyclonedx_exe = get_cyclonedx_path()
    trivy_exe = get_trivy_path()

    if not os.path.exists(cyclonedx_exe):
        raise HTTPException(500, "CycloneDX CLI non trovato.")

    if not os.path.exists(trivy_exe):
        raise HTTPException(500, "Trivy non trovato.")

    rq2_dir = os.path.join(STORAGE_DIR, "rq_results")
    os.makedirs(rq2_dir, exist_ok=True)

    merged_sbom = os.path.join(
        rq2_dir,
        "rq2_source_image_merged_sbom.json"
    )

    vulnerability_report = os.path.join(
        rq2_dir,
        "rq2_trivy_vulnerabilities.json"
    )

    try:
        subprocess.run(
            [
                cyclonedx_exe,
                "merge",
                "--input-files",
                *manifests_files,
                docker_sbom_file,
                "--output-file",
                merged_sbom,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            500,
            f"Merge SBOM RQ2 fallito: {e.stderr or e}"
        )

    # ========================================================
    # SCANSIONE DELLO SBOM APPENA GENERATO
    # ========================================================

    try:
        subprocess.run(
            [
                trivy_exe,
                "sbom",
                "--format", "json",
                "--output", vulnerability_report,
                merged_sbom,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            500,
            f"Scansione Trivy RQ2 fallita: {e.stderr or e}"
        )

    with open(vulnerability_report, "r", encoding="utf-8") as f:
        report = json.load(f)

    # ========================================================
    # COSTRUZIONE DEI COMPONENTI VULNERABILI
    # ========================================================

    vulnerable = {}

    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0,
    }

    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:

            pkg_identifier = vuln.get("PkgIdentifier") or {}
            purl = pkg_identifier.get("PURL") or ""

            name = vuln.get("PkgName") or ""
            version = vuln.get("InstalledVersion") or ""

            key = (
                normalize_purl(purl)
                if purl
                else f"nopurl:{name.lower()}@{version}"
            )

            severity = str(
                vuln.get("Severity") or "UNKNOWN"
            ).upper()

            if severity not in RQ2_SEVERITIES:
                severity = "UNKNOWN"

            cve_id = vuln.get("VulnerabilityID")

            if key not in vulnerable:
                vulnerable[key] = {
                    "name": name,
                    "version": version,
                    "purl": purl,
                    "cves": set(),
                    "max_severity": severity,
                }

            entry = vulnerable[key]

            if cve_id:
                entry["cves"].add(cve_id)

            if (
                severity_order[severity]
                > severity_order[entry["max_severity"]]
            ):
                entry["max_severity"] = severity


    # ---------- caratterizzazione sullo SBOM finale (nostra metodologia) ----------
    
    # Analisi originale: mantenuta per recuperare le informazioni
    # dei componenti dichiarati, come source_file e declared_version.
    analysis = analyze_source_components(STORAGE_DIR)

    if analysis.get("status") != "success":
        raise HTTPException(
            500,
            analysis.get(
                "message",
                "Caratterizzazione non riuscita (eseguire prima il merge)."
            )
        )

    # Nuova caratterizzazione: manifest + step Docker + deps.dev.
    char_map, char_error = rq23_get_depsdev_classification_map()

    if char_map is None:
        raise HTTPException(
            500,
            char_error or "Caratterizzazione deps.dev non riuscita."
        )

    declared_info = {
        normalize_purl(c["purl"]): c
        for c in analysis.get("declared", [])
        if c.get("purl")
    }

    
    declared_info = {
        normalize_purl(c["purl"]): c
        for c in analysis.get("declared", []) if c.get("purl")
    }

    for key, v in vulnerable.items():
        v["classification"] = char_map.get(key, "unmapped")

    total = len(vulnerable)

    # ---------- RQ2.1 ----------
    by_category = {cat: [v for v in vulnerable.values() if v["classification"] == cat] for cat in RQ2_CATEGORIES}
    target = [v for v in vulnerable.values() if v["classification"] in RQ2_TARGET]

    rq2_1 = {
        "total_vulnerable_components": total,
        "by_category": {
            cat: {"label": RQ2_LABELS[cat], "count": len(items), "pct_of_total": pct(len(items), total)}
            for cat, items in by_category.items()
        },
        "declared_vulnerable": len(by_category["declared"]),
        "unknown_direct_vulnerable": len(by_category["unknown"]),
        "declared_plus_unknown_direct": len(target),
        "declared_plus_unknown_direct_pct": pct(len(target), total),
    }

    # ---------- RQ2.2 ----------
    def sev_counts(items):
        counts = {s: 0 for s in RQ2_SEVERITIES}
        for it in items:
            counts[it["max_severity"]] += 1
        return counts

    target_sev = sev_counts(target)
    all_sev = sev_counts(vulnerable.values())

    rq2_2 = {
        "target_by_max_severity": target_sev,
        "all_by_max_severity": all_sev,
        "target_pct_of_all_by_severity": {s: pct(target_sev[s], all_sev[s]) for s in RQ2_SEVERITIES},
        "critical_or_high_in_target": target_sev["CRITICAL"] + target_sev["HIGH"],
        "unique_cves_in_target": len({cve for v in target for cve in v["cves"]}),
        "severity_by_category": {cat: sev_counts(items) for cat, items in by_category.items()},
    }

    # ---------- salvataggio ----------
    components_out = [
        {
            "name": v["name"],
            "version": v["version"],
            "purl": v["purl"],
            "classification": v["classification"],
            "classification_label": RQ2_LABELS[v["classification"]],
            "classic_classification": v.get("classic_classification"),
            "max_severity": v["max_severity"],
            "cves": sorted(v["cves"]),
            "cve_count": len(v["cves"]),
            "source_file": declared_info.get(normalize_purl(v["purl"]), {}).get("source_file") if v["purl"] else None,
            "declared_version": declared_info.get(normalize_purl(v["purl"]), {}).get("declared_version") if v["purl"] else None,
        }
        for v in target
    ]

    output = {
        "rq2_1": rq2_1,
        "rq2_2": rq2_2,
        "target_components": components_out,
    }

    out_dir = os.path.join(STORAGE_DIR, "rq_results")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "rq2_results.json"), "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    return {"status": "success", **output}

RQ23_OURS = ["declared", "transitive", "unknown", "transitive_unknown", "unmapped"]
RQ23_CLASSIC = ["declared", "transitive", "unknown"]  # la classica non distingue i due "sconosciuti"
RQ23_LABELS = {
    "declared": "Dichiarato",
    "transitive": "Transitivo",
    "unknown": "Sconosciuto diretto",
    "transitive_unknown": "Sconosciuto transitivo",
    "unmapped": "Non presente nel grafo",
}
RQ23_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
RQ23_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
RQ23_SOURCE_PATTERNS = ["*requirements*.txt", "*pyproject.toml", "*pom.xml", "*.gradle", "*.gradle.kts", "*.versions.toml"]
RQ23_OS_PREFIXES = ("pkg:deb/", "pkg:apk/", "pkg:rpm/")
 
 
def rq23_collapse(category):
    """La classica distingue solo dichiarati e transitivi: tutto il resto e' 'sconosciuto'."""
    return category if category in ("declared", "transitive") else "unknown"
 
 
def rq23_pick_severity(ratings):
    """Severita' del CVE dal blocco ratings di CycloneDX: preferisce la fonte NVD, altrimenti la piu' alta."""
    def norm(s):
        s = str(s or "").upper()
        return s if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "UNKNOWN"
 
    nvd = [
        norm(r.get("severity")) for r in ratings
        if "nvd" in str((r.get("source") or {}).get("name", "")).lower()
    ]
    pool = nvd or [norm(r.get("severity")) for r in ratings]
    return max(pool, key=lambda s: RQ23_SEV_RANK[s]) if pool else "UNKNOWN"
 
 
def rq23_namespace(purl):
    """Namespace del purl (groupId per Maven), in minuscolo; vuoto se assente."""
    m = re.match(r"^pkg:[^/]+/([^/@?#]+)/", unquote(purl or ""))
    return m.group(1).lower() if m else ""
 
 
def rq23_first_party_groups(paths):
    """groupId dei componenti radice degli SBOM (i moduli del progetto stesso)."""
    groups = set()
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        meta = (data.get("metadata") or {}).get("component") or {} if isinstance(data, dict) else {}
        if meta.get("group"):
            groups.add(str(meta["group"]).lower())
    return groups
 
 
def rq23_drop_first_party(comps, groups):
    """Toglie i componenti il cui namespace e' uno dei gruppi di prima parte. Ritorna (componenti, quanti tolti)."""
    if not groups:
        return comps, 0
    kept = {k: v for k, v in comps.items() if rq23_namespace(v["purl"]) not in groups}
    return kept, len(comps) - len(kept)
 
 
def rq23_load_sbom_components(paths):
    """Componenti unici (purl normalizzato) presenti in uno o piu' SBOM CycloneDX, con il componente originale."""
    comps = {}
 
    def walk(items):
        for c in items or []:
            if not isinstance(c, dict):
                continue
            purl = c.get("purl")
            if purl and c.get("type") not in IGNORED_TYPES:
                comps.setdefault(normalize_purl(purl), {
                    "name": c.get("name"),
                    "version": c.get("version"),
                    "purl": purl,
                    "raw": c,
                })
            walk(c.get("components"))
 
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        walk(data.get("components"))
    return comps
 
 
# ------------------------------------------------------------
# Aggregazione dei grafi (funziona anche con SBOM piatti)
# ------------------------------------------------------------
 
def rq23_collect_graph(paths, exclude_keys=None, skip_prefixes=()):
    """
    Aggrega piu' SBOM CycloneDX in un unico grafo: componenti unici (purl normalizzato) e relazioni
    genitore -> figlio. I riferimenti (bom-ref) sono risolti SBOM per SBOM, quindi non possono
    collidere tra file diversi. Un SBOM senza sezione dependencies contribuisce solo con i componenti.
    I nodi application/file/container/operating-system non sono componenti e non fanno da genitori.
    Ritorna (componenti {chiave: componente}, relazioni {chiave genitore: {chiavi figlie}}).
    """
    exclude_keys = exclude_keys or set()
    components, edges = {}, defaultdict(set)
 
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[WARNING] SBOM non leggibile {path}: {e}", flush=True)
            continue
        if not isinstance(data, dict):
            continue
 
        ref_to_key = {}
 
        def collect(items):
            for c in items or []:
                if not isinstance(c, dict):
                    continue
                purl = c.get("purl")
                if purl and c.get("type") not in IGNORED_TYPES:
                    key = normalize_purl(purl)
                    if key not in exclude_keys and not key.startswith(skip_prefixes):
                        if key not in components:
                            comp = dict(c)
                            comp.pop("components", None)
                            comp["bom-ref"] = purl
                            components[key] = comp
                        for ref in (c.get("bom-ref"), purl):
                            if ref:
                                ref_to_key[ref] = key
                collect(c.get("components"))
 
        collect(data.get("components"))
 
        for dep in data.get("dependencies") or []:
            parent = ref_to_key.get(dep.get("ref"))
            if not parent:
                continue
            for child_ref in dep.get("dependsOn") or []:
                child = ref_to_key.get(child_ref)
                if child and child != parent:
                    edges[parent].add(child)
 
    return components, edges
 
 
def rq23_write_aggregate(components, edges, out_path):
    """Scrive l'SBOM aggregato (bom-ref = purl), nel formato letto da analyze_source_components."""
    purl_of = {k: c["purl"] for k, c in components.items()}
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "components": list(components.values()),
        "dependencies": [
            {"ref": purl_of[p], "dependsOn": sorted(purl_of[c] for c in children if c in purl_of)}
            for p, children in edges.items() if p in purl_of
        ],
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, ensure_ascii=False)
 
 
def rq23_pairs(edges):
    return {(p, c) for p, children in edges.items() for c in children}
 
 
def rq23_graph_summary(components, edges, universe_keys):
    """Quante relazioni ha il grafo e per quanti componenti dell'universo da' almeno un genitore/figlio."""
    children = set()
    for ch in edges.values():
        children |= ch
    parents = {p for p, ch in edges.items() if ch}
    return {
        "components": len(components),
        "relations": sum(len(ch) for ch in edges.values()),
        "universe_with_parent": len(universe_keys & children),
        "universe_with_children": len(universe_keys & parents),
    }
 
 
def rq23_union_edges(*edge_maps):
    union = defaultdict(set)
    for m in edge_maps:
        for p, ch in m.items():
            union[p] |= ch
    return union
 
 
# ------------------------------------------------------------
# Vulnerabilita'
# ------------------------------------------------------------
 
def rq23_load_vulnerabilities(path):
    """{purl normalizzato: {cves:set, max_severity}} da uno SBOM CycloneDX con sezione vulnerabilities."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
 
    ref_to_key = {}
    for c in data.get("components", []):
        if c.get("purl") and c.get("bom-ref"):
            ref_to_key[c["bom-ref"]] = normalize_purl(c["purl"])
 
    out = {}
    for v in data.get("vulnerabilities") or []:
        severity = rq23_pick_severity(v.get("ratings") or [])
        for aff in v.get("affects") or []:
            ref = aff.get("ref")
            key = ref_to_key.get(ref)
            if not key and str(ref).startswith("pkg:"):
                key = normalize_purl(ref)
            if not key:
                continue
            entry = out.setdefault(key, {"cves": set(), "max_severity": "UNKNOWN"})
            entry["cves"].add(v.get("id"))
            if RQ23_SEV_RANK[severity] > RQ23_SEV_RANK[entry["max_severity"]]:
                entry["max_severity"] = severity
    return out
 
 
def rq23_scan_component(v):
    """Componente da passare a Trivy: l'originale (properties incluse) con i campi chiave normalizzati."""
    comp = dict(v.get("raw") or {})
    comp.pop("components", None)
    if comp.get("type") in (None, *IGNORED_TYPES):
        comp["type"] = "library"
    comp["bom-ref"] = v["purl"]
    comp["name"] = v["name"]
    comp["version"] = v["version"]
    comp["purl"] = v["purl"]
    return comp
 
 
def rq23_scan_vulnerabilities(components, workdir_name):
    """
    Scansiona con Trivy i componenti (SBOM piatto) e ritorna (mappa vulnerabilita', info).
    Esclusi: componenti senza purl/versione e pacchetti OS (deb/apk/rpm).
    """
    info = {"scanned": 0, "no_version_or_purl": 0, "skipped_os_packages": 0, "error": None}
    items = {}
    for k, v in components.items():
        if not v.get("purl") or not v.get("version"):
            info["no_version_or_purl"] += 1
        elif re.match(r"^pkg:(deb|apk|rpm)/", v["purl"]):
            info["skipped_os_packages"] += 1
        else:
            items[k] = v
    if not items:
        return {}, info
 
    trivy_exe = get_trivy_path()
    if not os.path.exists(trivy_exe):
        info["error"] = "Trivy non trovato."
        return {}, info
 
    workdir = os.path.join(STORAGE_DIR, "rq_results", workdir_name)
    shutil.rmtree(workdir, onerror=remove_readonly, ignore_errors=True)
    os.makedirs(workdir, exist_ok=True)
    in_path = os.path.join(workdir, "components_sbom.json")
    out_path = os.path.join(workdir, "vulnerabilities_sbom.json")
 
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "components": [rq23_scan_component(v) for v in items.values()],
    }
    with open(in_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, ensure_ascii=False)
 
    try:
        subprocess.run(
            [trivy_exe, "sbom", "--scanners", "vuln", "--format", "cyclonedx", "--output", out_path, in_path],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        info["error"] = (e.stderr or str(e))[-600:]
        return {}, info
 
    info["scanned"] = len(items)
    return rq23_load_vulnerabilities(out_path), info
 
 
# ------------------------------------------------------------
# Caratterizzazione
# ------------------------------------------------------------

def rq23_classification(
    files,
    workdir_name,
    source_sbom_files=None,
    exclude_keys=None,
    skip_prefixes=(),
):
    """
    Caratterizza i componenti attraverso il grafo aggregato degli SBOM
    ricevuti in files.

    files:
        SBOM utilizzati per costruire il grafo.

    source_sbom_files:
        SBOM sorgente utilizzati come fallback per individuare
        le dipendenze dichiarate.

    Restituisce:
        classification_map, origins, error
    """

    workdir = os.path.join(
        STORAGE_DIR,
        "rq_results",
        workdir_name,
    )

    shutil.rmtree(
        workdir,
        onerror=remove_readonly,
        ignore_errors=True,
    )
    os.makedirs(workdir, exist_ok=True)

    # Copia i manifest di dichiarazione nella directory temporanea,
    # così analyze_source_components può leggerli.
    for pattern in RQ23_SOURCE_PATTERNS:
        for src in glb.glob(os.path.join(STORAGE_DIR, pattern)):
            shutil.copy(
                src,
                os.path.join(workdir, os.path.basename(src)),
            )

    # Costruisce il grafo usando ESCLUSIVAMENTE gli SBOM ricevuti.
    components, edges = rq23_collect_graph(
        files,
        exclude_keys=exclude_keys,
        skip_prefixes=skip_prefixes,
    )

    aggregate_path = os.path.join(
        workdir,
        "final_merged_sbom.json",
    )

    rq23_write_aggregate(
        components,
        edges,
        aggregate_path,
    )

    # Analizza il grafo aggregato.
    analysis = analyze_source_components(
        workdir,
        source_sbom_paths=source_sbom_files,
    )

    if analysis.get("status") != "success":
        return (
            None,
            None,
            analysis.get(
                "message",
                "Caratterizzazione fallita.",
            ),
        )

    # Costruisce la mappa usando i PURL normalizzati.
    classification_map = build_classification_map(analysis)

    origins = {
        normalize_purl(c["purl"]): c.get("derived_from")
        for c in analysis.get("not_declared", [])
        if c.get("purl")
    }

    return classification_map, origins, None

 
def rq23_variant(rows, field):
    """Riepilogo per una variante di baseline classica (campo `field` delle righe)."""
    def empty_matrix():
        return {o: {c: 0 for c in RQ23_CLASSIC} for o in RQ23_OURS}
 
    matrix_all, matrix_vuln = empty_matrix(), empty_matrix()
    for r in rows:
        matrix_all[r["ours"]][r[field]] += 1
        if r["vulnerable"]:
            matrix_vuln[r["ours"]][r[field]] += 1
 
    # Componenti che la classica lascia nel gruppo "sconosciuto"
    unknown_all = [r for r in rows if r[field] == "unknown"]
    unknown_vuln = [r for r in unknown_all if r["vulnerable"]]
 
    by_ours_all = {o: sum(1 for r in unknown_all if r["ours"] == o) for o in RQ23_OURS}
    by_ours_vuln = {o: sum(1 for r in unknown_vuln if r["ours"] == o) for o in RQ23_OURS}
 
    direct = [r for r in unknown_vuln if r["ours"] in ("declared", "unknown")]
    indirect = [r for r in unknown_vuln if r["ours"] in ("transitive", "transitive_unknown")]
 
    # Azioni stimate: punti di intervento diretti + radici da cui derivano gli indiretti
    roots = {r["origin"] for r in indirect if r["origin"]}
    actions = {r["name"] for r in direct} | roots
 
    severity_by_ours = {
        o: {s: sum(1 for r in unknown_vuln if r["ours"] == o and r["severity"] == s) for s in RQ23_SEVERITIES}
        for o in RQ23_OURS
    }
 
    # Componenti che la classica non sapeva classificare e noi si': dichiarati o transitivi
    recovered = by_ours_all["declared"] + by_ours_all["transitive"]
 
    return {
        "available": True,
        "matrix_all": matrix_all,
        "matrix_vulnerable": matrix_vuln,
        "classic_unknown_components": len(unknown_all),
        "classic_unknown_vulnerable": len(unknown_vuln),
        "classic_unknown_by_ours": by_ours_all,
        "classic_unknown_vulnerable_by_ours": by_ours_vuln,
        "recovered_as_declared_or_transitive": recovered,
        "recovered_pct_of_classic_unknown": pct(recovered, len(unknown_all)),
        "vulnerable_directly_actionable": len(direct),
        "vulnerable_directly_actionable_pct": pct(len(direct), len(unknown_vuln)),
        "vulnerable_indirect": len(indirect),
        "distinct_roots_for_indirect": len(roots),
        "estimated_actions": len(actions),
        "severity_by_ours_category": severity_by_ours,
    }
 
 
def rq23_component_rows(rows, fields):
    """Elenco dei componenti vulnerabili nel formato usato dal frontend."""
    return [
        {
            "name": r["name"],
            "version": r["version"],
            "purl": r["purl"],
            "ours": r["ours"],
            "ours_label": RQ23_LABELS[r["ours"]],
            "origin": r["origin"],
            **{out_key: r[row_key] for out_key, row_key in fields.items()},
            "max_severity": r["severity"],
            "cves": r["cves"],
            "cve_count": len(r["cves"]),
        }
        for r in rows if r["vulnerable"]
    ]
 
 
def rq23_counts(rows, field, categories):
    return {c: sum(1 for r in rows if r[field] == c) for c in categories}
 

def rq23_depsdev_identity(purl):
    """Converte un PURL in un'identità confrontabile con deps.dev."""
    try:
        parsed = PackageURL.from_string(purl)
    except Exception:
        return None

    system = (parsed.type or "").lower()
    namespace = parsed.namespace or ""
    name = parsed.name or ""
    version = parsed.version or ""

    if not version:
        return None

    if system not in {"maven", "pypi", "cargo", "npm"}:
        return None

    if system == "maven":
        package_name = f"{namespace}:{name}" if namespace else name
    elif system == "npm":
        package_name = f"{namespace}/{name}" if namespace else name
    else:
        package_name = name

    if system == "pypi":
        # Normalizzazione dei nomi secondo la convenzione PyPI.
        package_name = re.sub(r"[-_.]+", "-", package_name).lower()
    else:
        package_name = package_name.lower()

    return system, package_name, version


def rq23_depsdev_node_identity(node):
    """Legge l'identità di un nodo restituito dall'API deps.dev."""
    version_key = (node or {}).get("versionKey") or {}

    system = str(version_key.get("system") or "").lower()
    package_name = str(version_key.get("name") or "")
    version = str(version_key.get("version") or "")

    if not system or not package_name or not version:
        return None

    if system == "pypi":
        package_name = re.sub(r"[-_.]+", "-", package_name).lower()
    else:
        package_name = package_name.lower()

    return system, package_name, version


def rq23_depsdev_fetch(purl, timeout=12):
    """
    Recupera il grafo delle dipendenze di un componente.
    Ritorna le relazioni come coppie di identità (padre, figlio).
    """
    identity = rq23_depsdev_identity(purl)
    if not identity:
        return set(), None

    system, package_name, version = identity

    url = (
        f"https://api.deps.dev/v3alpha/systems/{system}"
        f"/packages/{quote(package_name, safe=':@')}"
        f"/versions/{quote(version, safe='')}:dependencies"
    )

    try:
        response = requests.get(url, timeout=timeout)

        if response.status_code == 404:
            return set(), "versione non trovata in deps.dev"

        response.raise_for_status()
        data = response.json()

        nodes = data.get("nodes") or []
        edges = data.get("edges") or []

        node_identities = [
            rq23_depsdev_node_identity(node)
            for node in nodes
        ]

        relations = set()

        for edge in edges:
            source_index = edge.get("fromNode")
            target_index = edge.get("toNode")

            if not isinstance(source_index, int):
                continue
            if not isinstance(target_index, int):
                continue
            if source_index >= len(node_identities):
                continue
            if target_index >= len(node_identities):
                continue

            source = node_identities[source_index]
            target = node_identities[target_index]

            if source and target and source != target:
                relations.add((source, target))

        return relations, None

    except Exception as exc:
        return set(), str(exc)


def rq23_depsdev_enrich_image_graph(image, original_edges):
    """
    Integra gli archi deps.dev nel grafo.

    Vincolo fondamentale:
    entrambi gli estremi di ogni arco devono già appartenere
    all'universo dei componenti dello SBOM Docker.

    Non vengono creati nuovi nodi.
    """
    # Identità deps.dev -> chiave normalizzata del componente Docker.
    identity_to_key = {}

    for key, component in image.items():
        identity = rq23_depsdev_identity(component.get("purl", ""))

        if identity:
            identity_to_key.setdefault(identity, key)

    # original_edges è una mappa {padre: set(figli)}.
    original_pairs = {
        (parent, child)
        for parent, children in original_edges.items()
        for child in children
        if parent in image and child in image
    }

    # Query parallele per limitare il tempo totale.
    purls = [
        component.get("purl")
        for component in image.values()
        if component.get("purl")
        and rq23_depsdev_identity(component["purl"])
    ]

    all_api_relations = set()
    errors = []
    queried = 0

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(rq23_depsdev_fetch, purl): purl
            for purl in purls
        }

        for future in as_completed(futures):
            queried += 1
            purl = futures[future]

            try:
                relations, error = future.result()
            except Exception as exc:
                relations, error = set(), str(exc)

            if error:
                errors.append({
                    "purl": purl,
                    "error": error,
                })

            all_api_relations.update(relations)

    # Grafo finale: esclusivamente nodi già presenti nell'immagine.
    enriched_edges = defaultdict(set)

    for parent, child in original_pairs:
        enriched_edges[parent].add(child)

    added_edges = []

    for source_identity, target_identity in all_api_relations:
        source_key = identity_to_key.get(source_identity)
        target_key = identity_to_key.get(target_identity)

        # Non aggiungere nodi o relazioni verso componenti assenti.
        if source_key is None or target_key is None:
            continue

        if source_key == target_key:
            continue

        if target_key not in enriched_edges[source_key]:
            enriched_edges[source_key].add(target_key)

        if (source_key, target_key) not in original_pairs:
            added_edges.append({
                "source": source_key,
                "target": target_key,
                "source_purl": image[source_key]["purl"],
                "target_purl": image[target_key]["purl"],
                "source_name": image[source_key]["name"],
                "target_name": image[target_key]["name"],
                "source_version": image[source_key]["version"],
                "target_version": image[target_key]["version"],
                "origin": "deps.dev",
            })

    return {
        "edges": enriched_edges,
        "added_edges": added_edges,
        "stats": {
            "supported_components_queried": queried,
            "api_relations_returned": len(all_api_relations),
            "added_edges": len(added_edges),
            "api_errors": len(errors),
            "errors": errors,
        },
    }


def rq23_write_depsdev_sbom(image, added_edges, out_path):
    """
    Scrive uno SBOM ausiliario con i componenti dell'universo
    e i soli archi aggiunti da deps.dev.

    Lo SBOM è ausiliario: non modifica docker_sbom.json.
    """
    components = []

    for component in image.values():
        components.append({
            "type": "library",
            "bom-ref": component["purl"],
            "name": component["name"],
            "version": component["version"],
            "purl": component["purl"],
        })

    dependencies = [
        {
            "ref": edge["source_purl"],
            "dependsOn": [edge["target_purl"]],
        }
        for edge in added_edges
    ]

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
        "dependencies": dependencies,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, ensure_ascii=False, indent=2)

# Per la baseline classica manteniamo la definizione già usata:
# dichiarati + transitivi.
def characterized(counts):
    return (
        counts.get("declared", 0)
        + counts.get("transitive", 0)
    )

# Per il nuovo confronto, invece, un componente è classificato
# se appartiene a una delle quattro categorie esplicite.
# "unmapped" indica che non è stato classificato dal grafo.
def classified(counts):
    return sum(
        counts.get(category, 0)
        for category in (
            "declared",
            "transitive",
            "unknown",
            "transitive_unknown",
        )
    )


def rq23_get_depsdev_classification_map():
    """
    Restituisce la caratterizzazione dello scenario C:
    manifest + step Docker + relazioni deps.dev.

    L'universo dei componenti vulnerabili di RQ2.1
    non viene modificato da questa funzione.
    """
    docker_sbom_file = os.path.join(STORAGE_DIR, "docker_sbom.json")

    manifests_files = sorted(
        glb.glob(os.path.join(STORAGE_DIR, "manifests", "*.json"))
    )
    steps_files = sorted(
        glb.glob(os.path.join(STORAGE_DIR, "docker_sbom_steps", "*.json"))
    )

    if not os.path.exists(docker_sbom_file):
        return None, "docker_sbom.json non trovato."

    if not manifests_files:
        return None, "Nessuno SBOM trovato nella cartella manifests/."

    # Stesse opzioni predefinite di RQ2.3:
    # librerie soltanto, componenti rimossi esclusi.
    skip_prefixes = RQ23_OS_PREFIXES

    removed_keys = set()
    removed_path = os.path.join(
        STORAGE_DIR, "removed_components.json"
    )

    if os.path.exists(removed_path):
        with open(removed_path, "r", encoding="utf-8") as f:
            removed_data = json.load(f)

        removed_keys = {
            normalize_purl(c["purl"])
            for c in removed_data
            if isinstance(c, dict) and c.get("purl")
        }

    # Universo dell'immagine, come in RQ2.3.
    image = rq23_load_sbom_components([docker_sbom_file])

    image = {
        key: comp
        for key, comp in image.items()
        if not key.startswith(skip_prefixes)
    }

    manifests_steps_files = manifests_files + steps_files

    # Archi originali di manifest + step Docker.
    g_manifests = rq23_collect_graph(
        manifests_files,
        skip_prefixes=skip_prefixes,
    )

    g_steps = (
        rq23_collect_graph(
            steps_files,
            exclude_keys=removed_keys,
            skip_prefixes=skip_prefixes,
        )
        if steps_files
        else ({}, {})
    )

    source_steps_edges = rq23_union_edges(
        g_manifests[1],
        g_steps[1],
    )

    # Arricchimento deps.dev, vincolato ai componenti dell'immagine.
    depsdev_result = rq23_depsdev_enrich_image_graph(
        image,
        source_steps_edges,
    )

    depsdev_dir = os.path.join(
        STORAGE_DIR, "rq_results", "depsdev_graph"
    )
    os.makedirs(depsdev_dir, exist_ok=True)

    depsdev_sbom_file = os.path.join(
        depsdev_dir, "depsdev_edges_sbom.json"
    )

    rq23_write_depsdev_sbom(
        image,
        depsdev_result["added_edges"],
        depsdev_sbom_file,
    )

    # Stessa caratterizzazione dello scenario C di RQ2.3.
    classification_map, origins, error = rq23_classification(
        files=manifests_steps_files + [depsdev_sbom_file],
        workdir_name="docker_image_manifests_steps_depsdev",
        source_sbom_files=manifests_steps_files,
        exclude_keys=removed_keys,
        skip_prefixes=skip_prefixes,
    )

    if classification_map is None:
        return None, error or "Caratterizzazione deps.dev fallita."

    return classification_map, None


@router.get("/rq2-3-analysis")
def rq2_3_analysis(
    exclude_first_party: bool = False,
    libraries_only: bool = True,
    include_removed: bool = False,
):
    docker_sbom_file = os.path.join(STORAGE_DIR, "docker_sbom.json")
    vuln_sbom_file = os.path.join(STORAGE_DIR, "cyclonedx-vuln-SBOM.json")
    removed_path = os.path.join(STORAGE_DIR, "removed_components.json")

    manifests_files = sorted(
        glb.glob(os.path.join(STORAGE_DIR, "manifests", "*.json"))
    )
    steps_files = sorted(
        glb.glob(os.path.join(STORAGE_DIR, "docker_sbom_steps", "*.json"))
    )

    # ------------------------------------------------------------
    # Verifica degli input
    # ------------------------------------------------------------

    if not os.path.exists(docker_sbom_file):
        raise HTTPException(
            404,
            "docker_sbom.json non trovato. Generare prima lo SBOM Docker."
        )

    if not os.path.exists(vuln_sbom_file):
        raise HTTPException(
            404,
            "cyclonedx-vuln-SBOM.json non trovato. "
            "Rigenerare lo SBOM Docker (la action lo produce)."
        )

    if not manifests_files:
        raise HTTPException(
            404,
            "Nessun SBOM da sorgente in manifests/."
        )

    skip_prefixes = RQ23_OS_PREFIXES if libraries_only else ()

    first_party = (
        rq23_first_party_groups(manifests_files)
        if exclude_first_party
        else set()
    )

    # ------------------------------------------------------------
    # Componenti rimossi dal Dockerfile
    # ------------------------------------------------------------

    removed_keys = set()

    if not include_removed and os.path.exists(removed_path):
        with open(removed_path, "r", encoding="utf-8") as f:
            removed_data = json.load(f)

        removed_keys = {
            normalize_purl(c["purl"])
            for c in removed_data
            if isinstance(c, dict) and c.get("purl")
        }

    # ============================================================
    # UNIVERSO DI RIFERIMENTO
    #
    # L'universo è costituito ESCLUSIVAMENTE dai componenti presenti
    # in docker_sbom.json.
    #
    # docker_sbom.json NON verrà utilizzato per costruire i grafi
    # dei due scenari di caratterizzazione.
    # ============================================================

    image_all = rq23_load_sbom_components([docker_sbom_file])

    image = {
        key: comp
        for key, comp in image_all.items()
        if not key.startswith(skip_prefixes)
    }

    os_excluded = len(image_all) - len(image)

    image, image_first_party = rq23_drop_first_party(
        image,
        first_party,
    )

    universe = set(image)

    # ============================================================
    # STATISTICHE DEI GRAFI
    #
    # Manteniamo le statistiche già presenti nell'analisi.
    # Questi grafi servono per descrivere le relazioni, non per
    # aggiungere componenti all'universo da classificare.
    # ============================================================

    g_image = rq23_collect_graph(
        [docker_sbom_file],
        None,
        skip_prefixes,
    )

    g_manifests = rq23_collect_graph(
        manifests_files,
        None,
        skip_prefixes,
    )

    g_steps = (
        rq23_collect_graph(
            steps_files,
            removed_keys,
            skip_prefixes,
        )
        if steps_files
        else ({}, {})
    )

    union_components = {
        **g_steps[0],
        **g_manifests[0],
        **g_image[0],
    }

    union_edges = rq23_union_edges(
        g_image[1],
        g_manifests[1],
        g_steps[1],
    )

    pairs_image = rq23_pairs(g_image[1])
    pairs_manifests = rq23_pairs(g_manifests[1])
    pairs_steps = rq23_pairs(g_steps[1])

    graph_info = {
        "image": {
            **rq23_graph_summary(*g_image, universe),
            "flat": not pairs_image,
        },
        "manifests": rq23_graph_summary(
            *g_manifests,
            universe,
        ),
        "steps": {
            **rq23_graph_summary(*g_steps, universe),
            "files": len(steps_files),
        },
        "union": rq23_graph_summary(
            union_components,
            union_edges,
            universe,
        ),
        "relations_new_from_steps": len(
            pairs_steps - pairs_manifests - pairs_image
        ),
        "relations_new_from_image": len(
            pairs_image - pairs_manifests - pairs_steps
        ),
        "relations_new_from_manifests": len(
            pairs_manifests - pairs_image - pairs_steps
        ),
        "universe_components": len(universe),
    }

    # ============================================================
    # CARATTERIZZAZIONE DEI DUE SCENARI
    #
    # SCENARIO A:
    #   grafo costruito esclusivamente dagli SBOM in manifests/
    #
    # SCENARIO B:
    #   grafo costruito dagli SBOM in manifests/ e
    #   docker_sbom_steps/
    #
    # In entrambi gli scenari l'universo da classificare è image,
    # cioè quello proveniente da docker_sbom.json.
    #
    # docker_sbom.json NON viene passato a rq23_classification
    # in nessuno dei due scenari.
    # ============================================================

    # ------------------------------------------------------------
    # SCENARIO A: solo manifest
    # ------------------------------------------------------------

    manifests_map, manifests_origins, manifests_err = (
        rq23_classification(
            files=manifests_files,
            workdir_name="docker_image_manifests_only",
            source_sbom_files=manifests_files,
            exclude_keys=None,
            skip_prefixes=skip_prefixes,
        )
    )

    if manifests_map is None:
        raise HTTPException(
            500,
            f"Caratterizzazione con i soli manifest fallita: "
            f"{manifests_err}",
        )

    # ------------------------------------------------------------
    # SCENARIO B: manifest + step Docker
    #
    # Gli step vengono aggiunti al grafo, ma non viene aggiunto
    # docker_sbom.json.
    #
    # I componenti rimossi sono esclusi dal grafo secondo la
    # logica già prevista dal parametro include_removed.
    # ------------------------------------------------------------

    manifests_steps_files = manifests_files + steps_files

    manifests_steps_map, manifests_steps_origins, manifests_steps_err = (
        rq23_classification(
            files=manifests_steps_files,
            workdir_name="docker_image_manifests_and_steps",
            source_sbom_files=manifests_steps_files,
            exclude_keys=removed_keys,
            skip_prefixes=skip_prefixes,
        )
    )

    if manifests_steps_map is None:
        raise HTTPException(
            500,
            f"Caratterizzazione con manifest + step Docker fallita: "
            f"{manifests_steps_err}",
        )
    
    
    # ------------------------------------------------------------
    # SCENARIO C: manifest + step Docker + relazioni deps.dev
    # ------------------------------------------------------------

    # Per il confronto B -> C utilizziamo soltanto gli archi
    # di manifest e step, non quelli dello SBOM dell'immagine.
    source_steps_edges = rq23_union_edges(g_manifests[1], g_steps[1],)

    depsdev_result = rq23_depsdev_enrich_image_graph(image, source_steps_edges,)

    depsdev_edges = depsdev_result["added_edges"]
    depsdev_stats = depsdev_result["stats"]

    # Scrivo il file SBOM con le relazioni aggiunte da deps.dev
    depsdev_dir = os.path.join(STORAGE_DIR, "rq_results", "depsdev_graph",)
    os.makedirs(depsdev_dir, exist_ok=True)

    depsdev_sbom_file = os.path.join(depsdev_dir, "depsdev_edges_sbom.json",)

    rq23_write_depsdev_sbom(image, depsdev_edges, depsdev_sbom_file,)

    manifests_steps_depsdev_map, manifests_steps_depsdev_origins, depsdev_err = (
        rq23_classification(
            files=manifests_steps_files + [depsdev_sbom_file],
            workdir_name="docker_image_manifests_steps_depsdev",
            # I manifest e gli step restano la fonte per identificare
            # i componenti dichiarati; lo SBOM ausiliario aggiunge
            # soltanto relazioni.
            source_sbom_files=manifests_steps_files,
            exclude_keys=removed_keys,
            skip_prefixes=skip_prefixes,
        )
    )

    if manifests_steps_depsdev_map is None:
        raise HTTPException(
            500,
            f"Caratterizzazione con deps.dev fallita: {depsdev_err}",
        )


    # ------------------------------------------------------------
    # BASELINE CLASSICA PREESISTENTE
    #
    # Queste due caratterizzazioni vengono mantenute per non
    # eliminare le analisi e le statistiche già presenti.
    #
    # La baseline classica continua a distinguere dichiarato,
    # transitivo e sconosciuto.
    # ------------------------------------------------------------

    source_map, _, source_err = rq23_classification(
        files=manifests_files,
        workdir_name="classic_source_only",
        source_sbom_files=manifests_files,
        exclude_keys=None,
        skip_prefixes=skip_prefixes,
    )

    plus_map, _, plus_err = rq23_classification(
        files=manifests_files + [docker_sbom_file],
        workdir_name="classic_source_plus_image",
        source_sbom_files=manifests_files,
        exclude_keys=None,
        skip_prefixes=skip_prefixes,
    )

    # Per la nuova caratterizzazione principale utilizziamo
    # manifest + step, senza lo SBOM dell'immagine nel grafo.
    ours_map = manifests_steps_map
    ours_origins = manifests_steps_origins

    # ============================================================
    # VULNERABILITÀ DEI COMPONENTI DELL'IMMAGINE
    # ============================================================

    image_vulns = rq23_load_vulnerabilities(vuln_sbom_file)

    rows = []

    for key, comp in image.items():
        vuln = image_vulns.get(key)

        # Le categorie dei due scenari non vengono accorpate:
        # declared, transitive, unknown, transitive_unknown,
        # unmapped.
        manifests_category = manifests_map.get(key, "unmapped",)

        manifests_steps_category = manifests_steps_map.get(key, "unmapped",)
        
        manifests_steps_depsdev_category = (manifests_steps_depsdev_map.get(key, "unmapped"))

        # I campi source_only e source_plus_image sono mantenuti
        # per compatibilità con la baseline classica esistente.
        classic_source_category = rq23_collapse(
            (source_map or {}).get(key, "unmapped")
        )

        classic_plus_category = rq23_collapse(
            (plus_map or {}).get(key, "unmapped")
        )

        rows.append({
            "key": key,
            "name": comp["name"],
            "version": comp["version"],
            "purl": comp["purl"],

            # Campo storico: ora corrisponde allo scenario
            # manifest + step Docker.
            "ours": manifests_steps_category,
            "origin": manifests_steps_origins.get(key),

            # Nuovi campi per il confronto richiesto.
            "manifests_only": manifests_category,
            "manifests_only_origin": manifests_origins.get(key),

            "manifests_steps": manifests_steps_category,
            "manifests_steps_origin": manifests_steps_origins.get(key),

            # Campi della baseline classica: mantenuti.
            "source_only": classic_source_category,
            "source_plus_image": classic_plus_category,
            
            # Scenario C: manifest + step + deps.dev.
            "manifests_steps_depsdev": manifests_steps_depsdev_category,
            "manifests_steps_depsdev_origin": (
                manifests_steps_depsdev_origins.get(key)
            ),

            # Vulnerabilità.
            "vulnerable": vuln is not None,
            "severity": vuln["max_severity"] if vuln else None,
            "cves": sorted(
                x for x in vuln["cves"] if x
            ) if vuln else [],
        })

    vulnerable_rows = [
        r for r in rows
        if r["vulnerable"]
    ]

    # ============================================================
    # CONTEGGI DELLE CATEGORIE
    # ============================================================

    # Scenario B: manifest + step.
    counts_ours = rq23_counts(
        rows,
        "manifests_steps",
        RQ23_OURS,
    )

    # Scenario A: solo manifest.
    counts_manifests = rq23_counts(
        rows,
        "manifests_only",
        RQ23_OURS,
    )

    # Baseline classica: campi mantenuti.
    counts_source = rq23_counts(
        rows,
        "source_only",
        RQ23_CLASSIC,
    )

    counts_plus = rq23_counts(
        rows,
        "source_plus_image",
        RQ23_CLASSIC,
    )
    
    
    # Scenario C: manifest + step + deps.dev.
    counts_depsdev = rq23_counts(
        rows,
        "manifests_steps_depsdev",
        RQ23_OURS,
    )

    depsdev_classified = classified(counts_depsdev)

    # Componenti che cambiano categoria tra B e C.
    # In particolare, osserviamo gli sconosciuti e gli unmapped
    # prima dell'integrazione dell'API.
    depsdev_reclassified_components = [
        {
            "name": r["name"],
            "version": r["version"],
            "purl": r["purl"],
            "before": r["manifests_steps"],
            "after": r["manifests_steps_depsdev"],
            "vulnerable": r["vulnerable"],
            "max_severity": r["severity"],
            "cves": r["cves"],
            "cve_count": len(r["cves"]),
            "origin_before": r["manifests_steps_origin"],
            "origin_after": r["manifests_steps_depsdev_origin"],
        }
        for r in rows
        if r["manifests_steps"] in {
            "unknown",
            "transitive_unknown",
            "unmapped",
        }
        and r["manifests_steps_depsdev"] != r["manifests_steps"]
    ]

    # Sconosciuti che, dopo deps.dev, diventano dichiarati o transitivi.
    depsdev_recovered_components = [
        r for r in depsdev_reclassified_components
        if r["after"] in {"declared", "transitive"}
    ]

    depsdev_vulnerable_reclassified = [
        r for r in depsdev_reclassified_components
        if r["vulnerable"]
    ]


    
    manifests_classified = classified(counts_manifests)
    manifests_steps_classified = classified(counts_ours)

    # ============================================================
    # VARIANTI DELLA BASELINE CLASSICA
    # ============================================================

    variants = {
        "source_only": (
            rq23_variant(rows, "source_only")
            if source_map is not None
            else {
                "available": False,
                "error": source_err,
            }
        ),
        "source_plus_image": (
            rq23_variant(rows, "source_plus_image")
            if plus_map is not None
            else {
                "available": False,
                "error": plus_err,
            }
        ),
    }

    # ============================================================
    # UNIVERSO SORGENTE
    #
    # Manteniamo l'analisi dei componenti presenti negli SBOM
    # in manifests/, comprese le relative vulnerabilità.
    # ============================================================

    source_components = rq23_load_sbom_components(
        manifests_files
    )

    source_components, source_first_party = rq23_drop_first_party(
        source_components,
        first_party,
    )

    source_vulns, source_scan = rq23_scan_vulnerabilities(
        source_components,
        "source_vulnerability_scan",
    )

    source_rows = []

    for key, comp in source_components.items():
        vuln = source_vulns.get(key)

        category = (source_map or {}).get(
            key,
            "unmapped",
        )

        source_rows.append({
            "key": key,
            "name": comp["name"],
            "version": comp["version"],
            "purl": comp["purl"],

            # Caratterizzazione manifest + step.
            "ours": manifests_steps_map.get(
                key,
                "unmapped",
            ),
            "origin": manifests_steps_origins.get(key),

            # Caratterizzazione tramite soli manifest.
            "source_only_category": category,
            "classic": rq23_collapse(category),

            "vulnerable": vuln is not None,
            "severity": vuln["max_severity"] if vuln else None,
            "cves": sorted(
                x for x in vuln["cves"] if x
            ) if vuln else [],
        })

    source_vulnerable_rows = [
        r for r in source_rows
        if r["vulnerable"]
    ]

    # ============================================================
    # RISULTATI
    # ============================================================

    output = {
        "options": {
            "exclude_first_party": exclude_first_party,
            "libraries_only": libraries_only,
            "include_removed": include_removed,
            "first_party_groups": sorted(first_party),
            "step_files": len(steps_files),
        },

        "graph": graph_info,

        "image": {
            "components": len(rows),
            "vulnerable_components": len(vulnerable_rows),
            "os_excluded": os_excluded,
            "first_party_excluded": image_first_party,

            "vulnerabilities_without_component": len(
                set(image_vulns) - set(image_all)
            ),

            # Conteggi delle categorie per i due scenari.
            "classification_counts": {
                "manifests_only": counts_manifests,
                "manifests_steps": counts_ours,

                # Alias storici, mantenuti per compatibilità.
                "ours": counts_ours,
                "source_only": counts_source,
                "source_plus_image": counts_plus,
            },

            # Confronto diretto fra i due scenari.
            "characterization_comparison": {
                "universe_components": len(rows),

                "manifests_only": {
                    "counts": counts_manifests,
                    "classified_components": manifests_classified,
                    "classified_pct": pct(manifests_classified, len(rows)),
                    "unmapped_components": counts_manifests["unmapped"],
                    "unmapped_pct": pct(counts_manifests["unmapped"], len(rows)),
                },

                "manifests_steps": {
                    "counts": counts_ours,
                    "classified_components": manifests_steps_classified,
                    "classified_pct": pct(manifests_steps_classified, len(rows)),
                    "unmapped_components": counts_ours["unmapped"],
                    "unmapped_pct": pct(counts_ours["unmapped"], len(rows)),
                },

                "manifests_steps_depsdev": {
                    "counts": counts_depsdev,
                    "classified_components": depsdev_classified,
                    "classified_pct": pct(depsdev_classified, len(rows)),
                    "unmapped_components": counts_depsdev["unmapped"],
                    "unmapped_pct": pct(counts_depsdev["unmapped"], len(rows)),
                },

                "additional_classified_components": (
                    manifests_steps_classified - manifests_classified
                ),

                "additional_classified_pct_points": (
                    pct(manifests_steps_classified, len(rows))
                    - pct(manifests_classified, len(rows))
                ),

                "additional_classified_after_depsdev": (
                    depsdev_classified - manifests_steps_classified
                ),

                "additional_classified_after_depsdev_pct_points": (
                    pct(depsdev_classified, len(rows))
                    - pct(manifests_steps_classified, len(rows))
                ),
            },

            # Manteniamo anche la precedente statistica
            # "characterized", che conta dichiarati + transitivi.
            "characterized": {
                "ours": characterized(counts_ours),
                "source_only": characterized(counts_source),
                "source_plus_image": characterized(counts_plus),

                "ours_pct": pct(
                    characterized(counts_ours),
                    len(rows),
                ),
                "source_only_pct": pct(
                    characterized(counts_source),
                    len(rows),
                ),
                "source_plus_image_pct": pct(
                    characterized(counts_plus),
                    len(rows),
                ),
            },

            "not_in_graph": counts_ours["unmapped"],
            "not_in_graph_vulnerable": sum(
                1
                for r in vulnerable_rows
                if r["manifests_steps"] == "unmapped"
            ),
            
            "manifests_steps_depsdev": counts_depsdev,
        },

        "variants": variants,

        # Manteniamo l'elenco dei componenti vulnerabili e aggiungiamo
        # le categorie dei due scenari.
        "vulnerable_components": rq23_component_rows(
            rows,
            {
                "manifests_only": "manifests_only",
                "manifests_steps": "manifests_steps",
                "classic_source_only": "source_only",
                "classic_source_plus_image": "source_plus_image",
                "manifests_steps_depsdev": "manifests_steps_depsdev",
            },
        ),

        "source": {
            "components": len(source_rows),
            "vulnerable_components": len(source_vulnerable_rows),
            "first_party_excluded": source_first_party,

            "classification_available": source_map is not None,
            "classification_error": source_err,

            "classification_counts_source_only": rq23_counts(
                source_rows,
                "source_only_category",
                RQ23_OURS,
            ),

            "classification_counts_ours": rq23_counts(
                source_rows,
                "ours",
                RQ23_OURS,
            ),

            "vulnerability_scan": {
                **source_scan,
                "note": (
                    "Scansione Trivy dei componenti degli SBOM "
                    "in manifests/ (SBOM piatto con i componenti "
                    "originali). Pacchetti OS, componenti senza "
                    "purl o senza versione non sono scansionati."
                ),
            },

            "variants": {
                "source_only": (
                    rq23_variant(source_rows, "classic")
                    if source_map is not None
                    else {
                        "available": False,
                        "error": source_err,
                    }
                ),
            },

            "vulnerable_components": rq23_component_rows(
                source_vulnerable_rows,
                {
                    "classic_source_only": "classic",
                    "classic_source_plus_image": "classic",
                },
            ),
        },
        "newly_characterized_components": [
            row
            for row in rows
            if row.get("manifests_only") == "unmapped"
            and row.get("manifests_steps") in {
                "declared",
                "transitive",
                "unknown",
                "transitive_unknown",
            }
        ],
        "depsdev": {
            "stats": depsdev_stats,
            "added_edges": depsdev_edges,
            "reclassified_components": depsdev_reclassified_components,
            "recovered_components": depsdev_recovered_components,
            "vulnerable_reclassified_components": (
                depsdev_vulnerable_reclassified
            ),
        },
    }

    # ============================================================
    # SALVATAGGIO DEI RISULTATI
    # ============================================================

    out_dir = os.path.join(
        STORAGE_DIR,
        "rq_results",
    )

    os.makedirs(
        out_dir,
        exist_ok=True,
    )

    output_path = os.path.join(
        out_dir,
        "rq2_3_results.json",
    )

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(
            output,
            f,
            indent=4,
            ensure_ascii=False,
        )

    return {
        "status": "success",
        **output,
    }

 
 
@router.get("/search-component")
def search_component_endpoint(name:str):

    matches = search_component( name, STORAGE_DIR)

    graphs = []

    for item in matches:

        graph = build_component_graph( item["purl"], item["sbom"])

        graphs.append(
            {
                "sbom": item["sbom"],
                "component": item,
                "graph": graph
            }
        )

    print(f"[DEBUG] grafici: {graphs}", flush=True)

    return {
        "component":name,
        "matches":graphs
    }