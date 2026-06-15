from fastapi import FastAPI, HTTPException, Query, UploadFile, File
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
import io
from typing import Optional

load_dotenv()

app = FastAPI(title="TLSAssistant Dependency Analyzer Backend")

GITHUB_API = "https://api.github.com/repos"
MY_GITHUB_OWNER = os.getenv("MY_GITHUB_OWNER", "IlTuoNomeUtenteGitHub")
MY_GITHUB_REPO = os.getenv("MY_GITHUB_REPO", "IlNomeDellaTuaRepoDelTool")


# ============================================================
# AUTH GITHUB
# ============================================================

def github_headers():
    token = os.getenv("GITHUB_TOKEN")
    if token:
        return {"Authorization": f"Bearer {token}"}
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

    if version:
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

# ====================================================
# Analyze Repository (URL)
# ====================================================

@app.post("/analyze-repo")
def analyze_repo(repo_url: str, branch: str = "main", path_dipendenze: str = "dependencies.json"):

    tmp = tempfile.mkdtemp()

    try:
        # ====================================================
        # CLONE REPO
        # ====================================================
        subprocess.run([
            "git", "clone",
            "--depth", "1",
            "--branch", branch,
            repo_url,
            tmp
        ], check=True)

        # ====================================================
        # SEARCH dependencies.json
        # ====================================================
        target_file = None

        for root, _, files in os.walk(tmp):
            if path_dipendenze in files:
                target_file = os.path.join(root, path_dipendenze)
                break

        if not target_file:
            return {
                "status": "error",
                "message": f"{path_dipendenze} non trovato nella repository"
            }

        # ====================================================
        # LOAD FILE
        # ====================================================
        with open(target_file, "r", encoding="utf-8") as f:
            dependencies = json.load(f)

        if not isinstance(dependencies, list):
            return {
                "status": "error",
                "message": "dependencies.json non valido (deve essere una lista)"
            }

        # ====================================================
        # REUSE YOUR EXISTING LOGIC (inline analysis)
        # ====================================================
        extracted_data = []
        repos = []

        for item in dependencies:

            dep_type = item.get("type", "N/A")
            url_val = item.get("url") or item.get("path") or ""

            name, version, purl = extract(item)
            language = None
            component_type = classify(dep_type)

            github_repo = parse_github_url(item.get("url", ""))

            if github_repo != "N/A":
                repos.append(github_repo)

            extracted_data.append({
                "type": dep_type,
                "component_type": component_type,
                "name": name,
                "version": version,
                "purl": purl,
                "language": language,
                "github_repo": github_repo
            })

        # ====================================================
        # RETURN SAME FORMAT AS /analyze
        # ====================================================
        return {
            "status": "success",
            "repo": repo_url,
            "branch": branch,
            "count": len(extracted_data),
            "dependencies": extracted_data,
            "detected_git_repos": list(set(repos))
        }

    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ============================================================
# ANALYZE REPOSITORY (TRIGGER GITHUB ACTION)
# ============================================================
@app.post("/analyze-static")
async def analyze_static(
    repo_url: str, 
    branch: str = "main", 
    format_type: str = Query("entrambi", description="Opzioni: requirements, poetry, entrambi")
):
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise HTTPException(500, "GITHUB_TOKEN non trovato nel file .env")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    # TRIGGER DELLA PIPELINE TRAMITE REPOSITORY DISPATCH
    dispatch_url = f"https://api.github.com/repos/{MY_GITHUB_OWNER}/{MY_GITHUB_REPO}/dispatches"
    
    # Se viene passato un URL completo, estraiamo solo la parte owner/repo per evitare problemi di formattazione nella Action
    clean_repo = repo_url.replace("https://github.com/", "").rstrip("/")

    payload = {
        "event_type": "run_sbom_analysis",
        "client_payload": {
            "target_repository": clean_repo,
            "target_branch": branch,
            "format": format_type.lower()
        }
    }

    trigger_res = requests.post(dispatch_url, headers=headers, json=payload)
    if trigger_res.status_code != 204:
        raise HTTPException(400, f"Errore nell'avvio del workflow GitHub: {trigger_res.text}")

    # POLLING: Controllo lo stato della Run fino a completamento
    time.sleep(6) # Tempo minimo di inizializzazione su GitHub
    runs_url = f"https://api.github.com/repos/{MY_GITHUB_OWNER}/{MY_GITHUB_REPO}/actions/runs?event=repository_dispatch&per_page=1"
    
    run_id = None
    for _ in range(40): # Timeout massimo esteso (~6-7 minuti per build complesse)
        print("Controllo stato GitHub Action...")
        try:
            r = requests.get(runs_url, headers=headers).json()
            runs = r.get("workflow_runs", [])
            if runs:
                latest_run = runs[0]
                if latest_run.get("status") == "completed":
                    if latest_run.get("conclusion") == "success":
                        run_id = latest_run.get("id")
                        break
                    else:
                        raise HTTPException(500, f"GitHub Action fallita (Conclusion: {latest_run.get('conclusion')})")
        except Exception as e:
            if isinstance(e, HTTPException): raise e
            pass
        time.sleep(10)

    if not run_id:
        raise HTTPException(408, "Timeout: L'elaborazione su GitHub Actions ha superato il tempo massimo.")

    # DOWNLOAD E PARSING DEL CONFRONTO GENERATO
    artifacts_url = f"https://api.github.com/repos/{MY_GITHUB_OWNER}/{MY_GITHUB_REPO}/actions/runs/{run_id}/artifacts"
    artifacts_resp = requests.get(artifacts_url, headers=headers).json()
    artifacts = artifacts_resp.get("artifacts", [])

    if not artifacts:
        raise HTTPException(404, "La pipeline ha girato ma non ha prodotto file di Artifact (confronto_results).")

    # Scarichiamo il file zip dei risultati
    artifact_id = artifacts[0].get("id")
    download_url = f"https://api.github.com/repos/{MY_GITHUB_OWNER}/{MY_GITHUB_REPO}/actions/artifacts/{artifact_id}/zip"
    file_resp = requests.get(download_url, headers=headers)
    
    report_content = ""
    
    # Estraiamo in memoria il testo generato dal tuo script python (confronto_result_poetry.txt o requirements)
    with zipfile.ZipFile(io.BytesIO(file_resp.content)) as z:
        for filename in z.namelist():
            if filename.startswith("confronto_result_") and filename.endswith(".txt"):
                with z.open(filename) as f:
                    report_content += f"--- FILE: {filename} ---\n"
                    report_content += f.read().decode("utf-8") + "\n\n"

    return {
        "status": "success",
        "repository": clean_repo,
        "format": format_type,
        "github_run_url": f"https://github.com/{MY_GITHUB_OWNER}/{MY_GITHUB_REPO}/actions/runs/{run_id}",
        "comparison_matrix": report_content if report_content else "Nessun report testuale generato dagli script di confronto."
    }

# ============================================================
# ANALYZE FILES 
# ============================================================
from fastapi import FastAPI, UploadFile, File, HTTPException
from typing import Optional

# ... il resto del tuo codice backend ...

@app.post("/analyze-files")
async def analyze_files(
    repo_url: str,
    branch: str = "main",
    requirements_file: Optional[UploadFile] = File(None),
    poetry_file: Optional[UploadFile] = File(None)
):
   print ("Ricevuta richiesta di analisi manuale con file caricati:")
   print(f"Repo URL: {repo_url}")

# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)