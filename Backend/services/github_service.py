import os
import time
import shutil
import zipfile
import requests
from typing import Optional
from config import GITHUB_API, MY_GITHUB_OWNER, MY_GITHUB_REPO, GITHUB_REF, STORAGE_DIR

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
# TRIGGER GITHUB ACTION per avviare pipeline remote specifiche e recuperare URL e ID della run
# ============================================================

def trigger_github_action(workflow_file: str, inputs: dict) -> Optional[dict]:
    headers = github_headers()
    if not headers:
        print("[ERROR] GITHUB_TOKEN non trovato nelle variabili d'ambiente.")
        return None

    # URL dinamico basato sul file .yml passato come argomento
    url_dispatch = f"{GITHUB_API}/{MY_GITHUB_OWNER}/{MY_GITHUB_REPO}/actions/workflows/{workflow_file}/dispatches"
    payload = {
        "ref": GITHUB_REF,
        "inputs": inputs
    }

    try:
        res = requests.post(url_dispatch, headers=headers, json=payload, timeout=10)
        if res.status_code != 204:
            return None
    except Exception as err:
        return None

    time.sleep(6)
    
    url_runs = f"{GITHUB_API}/{MY_GITHUB_OWNER}/{MY_GITHUB_REPO}/actions/runs?per_page=1"
    try:
        res_runs = requests.get(url_runs, headers=headers, timeout=10)
        if res_runs.status_code == 200:
            runs = res_runs.json().get("workflow_runs", [])
            if runs:
                return {
                    "html_url": runs[0].get("html_url"),
                    "id": runs[0].get("id")
                }
    except Exception as err:
        print(f"[DEBUG X] Eccezione durante la GET delle runs: {err}", flush=True)
            
    return None

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
        return False

    # Download del pacchetto ZIP dell'artifact
    download_url = target_artifact["archive_download_url"]
    res_dl = requests.get(download_url, headers=headers, stream=True)
    if res_dl.status_code != 200:
        return False
    
    # Salvataggio del file ZIP in una posizione temporanea
    zip_path = os.path.join(dest_dir, "artifacts.zip")
    with open(zip_path, "wb") as f:
        shutil.copyfileobj(res_dl.raw, f)
    
    # Setup cartelle di destinazione
    manifests_dir = os.path.join(dest_dir, "manifests")
    deps_dir = os.path.join(dest_dir, "dependencies")
    os.makedirs(manifests_dir, exist_ok=True)
    os.makedirs(deps_dir, exist_ok=True)
    
    # Estrazione e smistamento immediato
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for file_name in zip_ref.namelist():
            if file_name.endswith(".json"):
                # Estrazione del file temporaneamente
                zip_ref.extract(file_name, dest_dir)
                file_path = os.path.join(dest_dir, file_name)
                
                # Smista in base al nome
                if file_name == "trivy_poetry.json" or file_name == "trivy_requirements.json" or file_name == "trivy_uv.json":
                    shutil.move(file_path, os.path.join(manifests_dir, file_name))
                elif file_name != "docker_sbom.json" and file_name != "cyclonedx-license-SBOM.json" and file_name != "cyclonedx-vuln-SBOM.json":
                    shutil.move(file_path, os.path.join(deps_dir, file_name))
    
    # Rimuovi lo zip dopo aver estratto
    if os.path.exists(zip_path):
        os.remove(zip_path)
        
    return True