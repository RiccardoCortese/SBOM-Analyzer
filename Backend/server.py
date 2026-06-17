from fastapi import FastAPI, HTTPException, UploadFile, File, Form
import json
import subprocess
from dotenv import load_dotenv
import os
import re
import requests
import tempfile
import shutil
import time
import zipfile
from typing import Optional

load_dotenv()

app = FastAPI(title="TLSAssistant Dependency Analyzer Backend")

STORAGE_DIR = os.path.join(tempfile.gettempdir(), "tlsassistant_storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

GITHUB_API = "https://api.github.com/repos"
MY_GITHUB_OWNER = os.getenv("MY_GITHUB_OWNER", "RiccardoCortese")
MY_GITHUB_REPO = os.getenv("MY_GITHUB_REPO", "SBOM-Analyzer")


# ============================================================
# AUTH GITHUB
# ============================================================

def github_headers():
    token = os.getenv("GITHUB_TOKEN")
    if token:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json"
        }
    return {}


# ============================================================
# GITHUB PARSER
# ============================================================

def parse_github_url(url: str) -> str:
    if not url or not isinstance(url, str):
        return "N/A"

    match = re.search(r"github\.com/([^/]+)/([^/?#]+)", url)

    if not match:
        return "N/A"

    owner = match.group(1)
    repo = match.group(2).replace(".git", "")

    return f"https://github.com/{owner}/{repo}"


# ============================================================
# PURL
# ============================================================

def build_purl(dep_type: str, name: str, version: str | None = None):
    if dep_type == "pip":
        return f"pkg:pypi/{name}" + (f"@{version}" if version else "")
    if dep_type == "apt":
        return f"pkg:deb/debian/{name}"
    if dep_type in ["git", "git-submodule"]:
        return f"pkg:github/{name}"
    if version and version != "unknown":
        return f"pkg:generic/{name}@{version}"
    return f"pkg:generic/{name}"


# ============================================================
# CLASSIFIER
# ============================================================

def classify(dep_type: str):
    return {
        "pip": "library",
        "apt": "system",
        "git": "app",
        "git-submodule": "app",
        "zip": "binary",
        "file": "data",
        "cfg": "config",
        "compile_maven": "build"
    }.get(dep_type, "unknown")


# ============================================================
# EXTRACT
# ============================================================

def extract(item):
    t = item.get("type")
    val = item.get("url") or item.get("path") or ""

    name = val
    version = "unknown"

    if t == "pip":
        if "==" in val:
            name, version = val.split("==")
    elif t in ["git", "git-submodule"]:
        repo = parse_github_url(val)
        if repo != "N/A":
            name = repo.split("/")[-1]
    elif t in ["zip", "file"]:
        name = val.split("/")[-1]

    purl = build_purl(t, name, None if version == "unknown" else version)
    return name, version, purl


# ============================================================
# LOGICA DI POLLING E SCARICAMENTO ARTIFACT
# ============================================================

def wait_and_download_artifacts(run_id: int, dest_dir: str):
    """Attende il completamento della Run e scarica qualsiasi artifact di tipo SBOM risultante."""
    headers = github_headers()
    url_run = f"{GITHUB_API}/{MY_GITHUB_OWNER}/{MY_GITHUB_REPO}/actions/runs/{run_id}"
    
    # Polling sullo stato della run (Timeout massimo 10 minuti)
    for _ in range(120):  
        print(f"Controllo stato run ID {run_id}...")
        res = requests.get(url_run, headers=headers)
        if res.status_code == 200:
            status = res.json().get("status")
            conclusion = res.json().get("conclusion")
            if status == "completed":
                if conclusion != "success":
                    raise Exception(f"La GitHub Action è terminata con stato: {conclusion}")
                break
        time.sleep(5)
    else:
        raise Exception("Timeout: La GitHub Action ha impiegato troppo tempo.")

    # Recupero dell'ID dell'Artifact
    url_artifacts = f"{url_run}/artifacts"
    res_art = requests.get(url_artifacts, headers=headers)
    if res_art.status_code != 200:
        return False

    artifacts = res_art.json().get("artifacts", [])
    
    # Rilevamento flessibile per supportare sia l'artifact statico singolo sia quelli multipli della matrice
    target_artifact = next((a for a in artifacts if "sbom" in a["name"].lower() or "results" in a["name"].lower() or "trivy" in a["name"].lower()), None)
    
    if not target_artifact:
        print("[DEBUG X] Nessun artifact contenente 'sbom' trovato per questa run.", flush=True)
        return False

    # Download del pacchetto ZIP dell'artifact
    download_url = target_artifact["archive_download_url"]
    res_dl = requests.get(download_url, headers=headers, stream=True)
    if res_dl.status_code == 200:
        zip_path = os.path.join(dest_dir, "artifacts.zip")
        with open(zip_path, "wb") as f:
            shutil.copyfileobj(res_dl.raw, f)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(dest_dir)
        return True
    
    return False


def trigger_github_action(workflow_file: str, inputs: dict) -> Optional[dict]:
    """Innesca una pipeline remota specifica e restituisce un dizionario con URL e Run ID."""
    print(f"[DEBUG 1] Entrato in trigger_github_action per {workflow_file}", flush=True)
    headers = github_headers()
    if not headers:
        print("[DEBUG X] ERRORE: GITHUB_TOKEN non trovato o vuoto nelle variabili d'ambiente!", flush=True)
        return None

    # URL dinamico basato sul file .yml passato come argomento
    url_dispatch = f"{GITHUB_API}/{MY_GITHUB_OWNER}/{MY_GITHUB_REPO}/actions/workflows/{workflow_file}/dispatches"
    payload = {
        "ref": "main",
        "inputs": inputs
    }

    print(f"[DEBUG 2] Invio POST a workflow dispatch... URL: {url_dispatch}", flush=True)
    try:
        res = requests.post(url_dispatch, headers=headers, json=payload, timeout=10)
        print(f"[DEBUG 3] Risposta POST dispatch: Stato {res.status_code}", flush=True)
        if res.status_code != 204:
            print(f"[DEBUG X] Errore da GitHub Dispatch: {res.text}", flush=True)
            return None
    except Exception as err:
        print(f"[DEBUG X] Eccezione durante la POST di dispatch: {err}", flush=True)
        return None

    print("[DEBUG 4] Attesa di 6 secondi per la registrazione della run...", flush=True)
    time.sleep(6)
    
    url_runs = f"{GITHUB_API}/{MY_GITHUB_OWNER}/{MY_GITHUB_REPO}/actions/runs?per_page=1"
    print(f"[DEBUG 5] Recupero l'ultima run dall'URL: {url_runs}", flush=True)
    try:
        res_runs = requests.get(url_runs, headers=headers, timeout=10)
        if res_runs.status_code == 200:
            runs = res_runs.json().get("workflow_runs", [])
            if runs:
                print(f"[DEBUG 6] Trovata run ID: {runs[0].get('id')}", flush=True)
                return {
                    "html_url": runs[0].get("html_url"),
                    "id": runs[0].get("id")
                }
            print("[DEBUG X] Nessuna run trovata nella lista dei workflow_runs.", flush=True)
    except Exception as err:
        print(f"[DEBUG X] Eccezione durante la GET delle runs: {err}", flush=True)
            
    return None


# ============================================================
# ACQUISIZIONE E SALVATAGGIO IN MEMORIA SERVER
# ============================================================

@app.post("/upload-sbom")
async def upload_sbom(
    action: str = Form(...),
    requirements_file: Optional[UploadFile] = File(None),
    poetry_file: Optional[UploadFile] = File(None),
    docker_file: Optional[UploadFile] = File(None), 
):
    if os.path.exists(STORAGE_DIR):
        shutil.rmtree(STORAGE_DIR)
    os.makedirs(STORAGE_DIR, exist_ok=True)

    if action == "upload":
        if not requirements_file and not poetry_file and not docker_file:
            raise HTTPException(400, "Carica almeno un file JSON.")

        if requirements_file:
            with open(os.path.join(STORAGE_DIR, "trivy_requirements.json"), "wb") as f:
                f.write(await requirements_file.read())

        if poetry_file:
            with open(os.path.join(STORAGE_DIR, "trivy_poetry.json"), "wb") as f:
                f.write(await poetry_file.read())

        if docker_file: 
            with open(os.path.join(STORAGE_DIR, "docker_sbom.json"), "wb") as f:
                f.write(await docker_file.read())

        return {"status": "success", "message": "File manuali salvati sul server."}

    elif action == "generate":
        if docker_file:
            with open(os.path.join(STORAGE_DIR, "docker_sbom.json"), "wb") as f:
                f.write(await docker_file.read())
        return {"status": "success", "message": "Pronto per l'attivazione della pipeline di generazione remota."}


# ============================================================
# ANALISI COMPARATIVA INTEGRATA
# ============================================================

@app.post("/compare-dependencies")
def compare_dependencies(repo_url: str, branch: str, path_dipendenze: str, format: str = "entrambi"):
    tmp_clone = tempfile.mkdtemp()
    try:
        github_run_url = None
        
        print("[BACKEND] Avvio trigger_github_action...", flush=True)
        
        match = re.search(r"github\.com/([^/]+)/([^/?#]+)", repo_url)
        owner_repo = f"{match.group(1)}/{match.group(2).replace('.git', '')}" if match else repo_url

        if format != "manual_only":
            old_inputs = {
                "src_repository": owner_repo,
                "src_branch": branch,
                "format": format
            }
            
            action_info = trigger_github_action("sbom_static.yml", old_inputs)
            print(f"DEBUG: Risultato trigger_github_action -> {action_info}", flush=True)
            if action_info:
                github_run_url = action_info["html_url"]
                wait_and_download_artifacts(action_info["id"], STORAGE_DIR)

        subprocess.run([
            "git", "clone", "--depth", "1", "--branch", branch, repo_url, tmp_clone
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        target_file = None
        for root, _, files in os.walk(tmp_clone):
            if path_dipendenze in files:
                target_file = os.path.join(root, path_dipendenze)
                break

        if not target_file:
            raise HTTPException(404, f"File '{path_dipendenze}' non trovato nella repository.")

        with open(target_file, "r", encoding="utf-8") as f:
            dependencies = json.load(f)

        if not isinstance(dependencies, list):
            raise HTTPException(400, "Il file delle dipendenze deve essere una lista JSON.")

        docker_path = os.path.join(STORAGE_DIR, "docker_sbom.json")
        docker_components = []
        if os.path.exists(docker_path):
            try:
                with open(docker_path, "r", encoding="utf-8") as f:
                    d_data = json.load(f)
                raw_list = d_data.get("components", []) if isinstance(d_data, dict) else (d_data if isinstance(d_data, list) else [])
                for c in raw_list:
                    if isinstance(c, dict):
                        docker_components.append({
                            "name": c.get("name", "unknown"),
                            "version": c.get("version", "unknown"),
                            "purl": c.get("purl", "")
                        })
            except Exception:
                pass

        def extract_identifiers(file_name):
            file_path = os.path.join(STORAGE_DIR, file_name)
            if not os.path.exists(file_path):
                return set()
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                identifiers = set()
                components_list = []

                if isinstance(data, dict) and "components" in data:
                    components_list = data["components"]
                elif isinstance(data, dict) and "artifacts" in data:
                    components_list = data["artifacts"]
                elif isinstance(data, list):
                    components_list = data

                for item in components_list:
                    if isinstance(item, dict):
                        name = item.get("name")
                        if name: identifiers.add(str(name).lower().strip())
                    elif isinstance(item, str):
                        identifiers.add(item.lower().strip())
                return identifiers
            except Exception:
                return set()

        # Carichiamo gli identificatori reali estratti da Trivy
        req_identifiers = extract_identifiers("trivy_requirements.json")
        poetry_identifiers = extract_identifiers("trivy_poetry.json")

        extracted_data = []
        repos = []
        
        # Insiemi cumulativi totali del codice (dependencies + trivy requirements + trivy poetry)
        all_code_names = set()
        all_code_purls = set()

        # Popoliamo inizialmente con i dati provenienti da Trivy
        for name_req in req_identifiers:
            all_code_names.add(name_req)
            all_code_purls.add(f"pkg:pypi/{name_req}")
            
        for name_poe in poetry_identifiers:
            all_code_names.add(name_poe)
            all_code_purls.add(f"pkg:pypi/{name_poe}")

        # Analizziamo la lista dependencies.json
        for item in dependencies:
            dep_type = item.get("type", "N/A")
            name, version, purl = extract(item)
            component_type = classify(dep_type)
            github_repo = parse_github_url(item.get("url", ""))

            if github_repo != "N/A":
                repos.append(github_repo)

            name_clean = str(name).lower().strip()
            all_code_names.add(name_clean)
            if purl:
                all_code_purls.add(purl.split("@")[0].lower().strip())

            is_in_req = "✅" if name_clean in req_identifiers else "❌"
            is_in_poetry = "✅" if name_clean in poetry_identifiers else "❌"

            extracted_data.append({
                "type": dep_type,
                "component_type": component_type,
                "name": name,
                "version": version,
                "purl": purl,
                "url": item.get("url") or item.get("path") or "",
                "github_repo": github_repo,
                "present_in_requirements": is_in_req,
                "present_in_poetry": is_in_poetry
            })
        
        
        in_common = []
        only_in_docker = []

        for dc in docker_components:
            dc_name_clean = dc["name"].lower().strip()
            dc_purl_clean = dc["purl"].split("@")[0].lower().strip() if dc["purl"] else ""

            # Controllo incrociato completo (Nome o PURL parziale presente ovunque)
            match_found = False
            if dc_name_clean in all_code_names:
                match_found = True
            elif dc_purl_clean:
                if dc_purl_clean in all_code_purls:
                    match_found = True
                else:
                    # Fallback per pURL generici o controlli substring
                    for cp in all_code_purls:
                        if dc_purl_clean in cp or cp in dc_purl_clean:
                            match_found = True
                            break

            if match_found:
                in_common.append(dc)
            else:
                only_in_docker.append(dc)

        docker_report = {
            "total_docker_packages": len(docker_components),
            "packages_in_common_count": len(in_common),
            "packages_only_in_docker_count": len(only_in_docker),
            "in_common": in_common,
            "only_in_docker": only_in_docker
        }

        def read_raw_file(file_name):
            file_path = os.path.join(STORAGE_DIR, file_name)
            if os.path.exists(file_path):
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        return f.read()
                except Exception:
                    return None
            return None

        raw_requirements = read_raw_file("trivy_requirements.json")
        raw_poetry = read_raw_file("trivy_poetry.json")

        simulated_matrix = (
            f"=== REPORT REALE PIPELINE ACTIONS ===\n"
            f"Componenti estratti dal file dinamico: {len(extracted_data)}\n"
            f"Trovati in Trivy (Requirements): {len([e for e in extracted_data if e['present_in_requirements'] == '✅'])}\n"
            f"Trovati in Trivy (Poetry): {len([e for e in extracted_data if e['present_in_poetry'] == '✅'])}\n"
        )

        return {
            "status": "success",
            "repo": repo_url,
            "branch": branch,
            "count": len(extracted_data),
            "result": extracted_data,
            "detected_git_repos": list(set(repos)),
            "github_run_url": github_run_url,
            "comparison_matrix": simulated_matrix,
            "raw_requirements": raw_requirements,
            "raw_poetry": raw_poetry,
            "docker_report": docker_report 
        }

    except Exception as e:
        print(f"[CRITICAL ERROR] Qualcosa è fallito catastroficamente: {str(e)}", flush=True)
        raise HTTPException(500, f"Errore interno del server: {str(e)}")
    finally:
        shutil.rmtree(tmp_clone, ignore_errors=True)


# ============================================================
# ANALISI COMPONENTI DEPENDENCIES.JSON IN PARALLELO
# ============================================================

@app.post("/analyze-dependencies-sbom")
def analyze_dependencies_sbom(repo_url: str, branch: str, path_dipendenze: str = "dependencies.json"):
    workflow_name = "dynamic_sbom.yml"
    print(f"[BACKEND] Innesco pipeline avanzata per singole dipendenze...", flush=True)
    
    match = re.search(r"github\.com/([^/]+)/([^/?#]+)", repo_url)
    owner_repo = f"{match.group(1)}/{match.group(2).replace('.git', '')}" if match else repo_url
    
    inputs = {
        "src_repository": owner_repo,
        "src_branch": branch,
        "path_dipendenze": path_dipendenze
    }
    run_info = trigger_github_action(workflow_name, inputs)
    
    if not run_info:
        raise HTTPException(status_code=500, detail="Impossibile avviare il workflow 'dynamic_sbom.yml' su GitHub. Verifica i log del server.")
        
    run_id = run_info["id"]
    github_run_url = run_info["html_url"]
    
    print(f"[BACKEND] Pipeline avviata con Run ID: {run_id}. Inizio polling...", flush=True)
    
    try:
        wait_and_download_artifacts(run_id, STORAGE_DIR)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Errore durante il polling degli artifact: {str(e)}")
        
    generated_sboms = {}
    
    if os.path.exists(STORAGE_DIR):
        print(f"[BACKEND] Lettura file scaricati in: {STORAGE_DIR}", flush=True)
        for file_name in os.listdir(STORAGE_DIR):
            if file_name.endswith("-sbom.json"):
                file_path = os.path.join(STORAGE_DIR, file_name)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        generated_sboms[file_name] = f.read()
                    print(f"[BACKEND] Caricato con successo lo SBOM per: {file_name}", flush=True)
                except Exception as e:
                    print(f"[BACKEND] Errore nella lettura del file {file_name}: {str(e)}", flush=True)

    return {
        "status": "success",
        "github_run_url": github_run_url,
        "sboms": generated_sboms
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)