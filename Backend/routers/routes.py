import os
import json
import shutil
import subprocess
import fnmatch
import stat
import glob as glb
import re
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from typing import Optional
from collections import defaultdict 
from urllib.parse import unquote

from config import STORAGE_DIR, STANDARD_FILE_ANALYZED
from utils.tools import get_cyclonedx_path
from services.github_service import trigger_github_action, wait_and_download_artifacts
from services.sbom_parser import (
    get_docker_analysis, generate_graphs_for_folder, 
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

    command = [
        trivy_exe,
        "sbom",
        "--format",
        "json",
        "--output",
        vulnerability_report,
        final_sbom,
    ]

    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Errore durante scansione Trivy: {e.stderr}",
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
    vuln_type: str = "os,library"
):
    
    os.makedirs(os.path.join(STORAGE_DIR, "manifests"), exist_ok=True)
    os.makedirs(os.path.join(STORAGE_DIR, "dependencies"), exist_ok=True)
    
    print(f"[BACKEND] Avvio pipeline Docker per l'immagine: {docker_target}", flush=True)
    
    # Allineamento Input con la tua GitHub Action (image_repository)
    docker_inputs = {
        "image_repository": docker_target,
        "src_vuln_type": vuln_type
    }
    
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

    # Generazione dei grafi per la visualizzazione nel frontend
    docker_graph_results = build_universal_hierarchy("docker_sbom.json", STORAGE_DIR)
    
    # calcolo per il peso di ogni dipendenza nel grafo
    memo = {}
    hierarchy_with_weights = {}
    
    
    for purl in docker_graph_results:
        stats = get_dependency_weight(purl, docker_graph_results, memo, visited_global=set())
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
        
    
        
    return {
        "status": "success", 
        "github_run_url": docker_action_info["html_url"], 
        "message": "SBOM Docker generato, scaricato e confrontato con successo.",
        "docker_report": docker_report,
        "raw_docker_sbom": raw_docker_sbom,
        "graphs": docker_graph_results,
        "hierarchy_with_weights": hierarchy_with_weights
    }
    
    
# ============================================================
# RQ1 / RQ1.1: componenti aggiuntivi rispetto alla scansione classica
# ============================================================
 
IGNORED_TYPES = {"application", "file", "container"}  # nodi "contenitore" di Trivy, non componenti reali
 
 
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
    scanned_keys = set()
    scan_errors = []
    scanned_by_group = {}
 
    suffix = "with_removed" if include_removed else "without_removed"
    SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
 
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
        components = [
            {
                "type": "library",
                "bom-ref": v["purl"],
                "name": v["name"],
                "version": v["version"],
                "purl": v["purl"],
            }
            for v in group.values()
        ]
 
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
                [trivy_exe, "sbom", "--format", "json", "--output", report_path, additional_sbom_path],
                check=True, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            scan_errors.append({
                "group": group_name,
                "components": len(group),
                "error": (e.stderr or str(e))[-600:],
            })
            continue
 
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
 
        scanned_keys.update(group.keys())
        scanned_by_group[group_name] = len(group)
 
        for res in report.get("Results", []):
            for vuln in res.get("Vulnerabilities") or []:
                purl = vuln.get("PkgIdentifier", {}).get("PURL", "")
                key = normalize_purl(purl) if purl else None
                if key not in additional:
                    continue  # Trivy può riportare componenti non nostri
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
 

    rq1_1 = {
        "scanned_components": len(scanned_keys),
        "not_scannable_components": len(additional) - len(scanned_keys),
        "not_scannable_no_purl_or_version": len(additional) - len(scannable),
        "scan_failed_components": len(scannable) - len(scanned_keys),
        "scanned_by_group": scanned_by_group,
        "scan_errors": scan_errors,
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
            {**{k2: v2 for k2, v2 in c.items() if k2 != "sources"}, "sources": sorted(c["sources"]), "key": k}
            for k, c in additional.items()
        ],
        "vulnerable_additional_components": list(vulnerable.values()),
    }
    with open(os.path.join(STORAGE_DIR, f"rq1_results_{suffix}.json"), "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)
 
    return {"status": "success", **output}

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
    grouped_path = os.path.join(STORAGE_DIR, "grouped_vulnerabilities.json")
    if not os.path.exists(grouped_path):
        raise HTTPException(404, "grouped_vulnerabilities.json non trovato. Eseguire prima la scansione vulnerabilità (scan-merged-sbom).")

    with open(grouped_path, "r", encoding="utf-8") as f:
        grouped = json.load(f).get("components", [])

    # ---------- componenti vulnerabili (chiave = purl normalizzato) ----------
    vulnerable = {}
    for c in grouped:
        purl = c.get("PURL") or ""
        key = normalize_purl(purl) if purl else f"nopurl:{str(c.get('Pacchetto', '')).lower()}@{c.get('Versione', '')}"
        sev = str(c.get("Severity", "UNKNOWN")).upper()
        if sev not in RQ2_SEVERITIES:
            sev = "UNKNOWN"
        cves = [x for x in c.get("CVE", []) if x]

        if key not in vulnerable:
            vulnerable[key] = {
                "name": c.get("Pacchetto"),
                "version": c.get("Versione"),
                "purl": purl,
                "cves": set(cves),
                "max_severity": sev,
            }
        else:
            entry = vulnerable[key]
            entry["cves"].update(cves)
            if RQ2_SEVERITIES.index(sev) < RQ2_SEVERITIES.index(entry["max_severity"]):
                entry["max_severity"] = sev

    # ---------- caratterizzazione sullo SBOM finale (nostra metodologia) ----------
    analysis = analyze_source_components(STORAGE_DIR)
    if analysis.get("status") != "success":
        raise HTTPException(500, analysis.get("message", "Caratterizzazione non riuscita (eseguire prima il merge)."))
    char_map = build_classification_map(analysis)
    
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

    # ---------- RQ2.3: confronto con la metodologia classica ----------
    classic_map, classic_error = classic_classification_map()

    rq2_3 = {"available": classic_map is not None, "error": classic_error}

    if classic_map is not None:
        for v in vulnerable.values():
            key = normalize_purl(v["purl"]) if v["purl"] else None
            v["classic_classification"] = classic_map.get(key, "absent") if key else "absent"

        # matrice nostra caratterizzazione -> caratterizzazione sul grafo classico
        transitions = {}
        for v in vulnerable.values():
            t = f"{v['classification']} -> {v['classic_classification']}"
            transitions[t] = transitions.get(t, 0) + 1

        absent = [v for v in target if v["classic_classification"] == "absent"]
        unresolved = [v for v in target if v["classic_classification"] in ("unknown", "transitive_unknown")]
        characterized = [v for v in target if v["classic_classification"] in ("declared", "transitive")]
        not_char = len(absent) + len(unresolved)

        rq2_3.update({
            "target_total": len(target),
            "not_characterizable_classic": not_char,
            "not_characterizable_classic_pct_of_target": pct(not_char, len(target)),
            "not_characterizable_classic_pct_of_all_vulnerable": pct(not_char, total),
            "absent_in_classic_sbom": len(absent),
            "present_but_unresolved_in_classic": len(unresolved),
            "characterizable_classic": len(characterized),
            "transitions": transitions,
        })

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
        "rq2_3": rq2_3,
        "target_components": components_out,
    }

    out_dir = os.path.join(STORAGE_DIR, "rq_results")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "rq2_results.json"), "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    return {"status": "success", **output}
    
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