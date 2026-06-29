from weakref import ref

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
import traceback
from typing import Optional
from dockerfile_parse import DockerfileParser
import stat

# ============================================================
# CONFIGURAZIONE INIZIALE E VARIABILI GLOBALI
# ============================================================
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
# GITHUB PARSER per estrarre il nome del repository da una URL e formattarlo in modo standard 
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
# PURL: GENERAZIONE DI UN IDENTIFICATORE UNIVOCO IN FORMATO PURL PER OGNI COMPONENTE, BASATO SUL TIPO E SULLE INFORMAZIONI DISPONIBILI
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
# EXTRACT: ESTRAZIONE DI NOME, VERSIONE E PURL DA UN OGGETTO DIPENDENZA, CON LOGICA SPECIFICA PER OGNI TIPO
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
# GRAPH DATA EXTRACTION per visualizzazione grafo
# ============================================================
def extract_graph_data(sbom_content):
    try:
        data = json.loads(sbom_content)
        nodes = []
        edges = []
        
        # Estrazione Nodi (usa 'bom-ref' come ID univoco se presente)
        components = data.get("components", [])
        for comp in components:
            node_id = comp.get("bom-ref") or comp.get("name")
            nodes.append({
                "id": node_id,
                "label": comp.get("name")
            })
            
        # Estrazione Archi (Dipendenze)
        dependencies = data.get("dependencies", [])
        for dep in dependencies:
            source = dep.get("ref")
            for child in dep.get("dependsOn", []):
                edges.append({
                    "source": source,
                    "target": child
                })
        return {"nodes": nodes, "edges": edges}
    except Exception as e:
        print(f"[ERROR] Fallimento estrazione grafo: {e}")
        return {"nodes": [], "edges": []}
    
def generate_graphs_for_folder(folder_path):
    graphs = {}
    if not os.path.exists(folder_path):
        return graphs
    for file_name in os.listdir(folder_path):
        if file_name.endswith(".json"):
            file_path = os.path.join(folder_path, file_name)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    graphs[file_name] = extract_graph_data(content)
            except Exception as e:
                print(f"[ERROR] Impossibile generare grafo per {file_name}: {e}")
    return graphs

# ============================================================
# FUNZIONE DI SUPPORTO CHE RITORNA UN DIZIONARIO CON TUTTE LE DIPENDENZE DI TUTTI I FILE TROVATI NELLA CARTELLA STORAGE (poetry.lock, requirements.txt, dependencies.json)
# ============================================================

def get_all_dependecies(content):
    try:
        data = json.loads(content)
        refs = []
        deps = []
        
        # Estrazione riderimenti (usa 'bom-ref' come ID univoco se presente)
        components = data.get("components", [])
        for comp in components:
            ref_id = comp.get("bom-ref") or comp.get("name")
            refs.append({
                "id": ref_id,
                "label": comp.get("name")
            })
            
        # Estrazione Dipendenze
        dependencies = data.get("dependencies", [])
        for dep in dependencies:
            source = dep.get("ref")
            for child in dep.get("dependsOn", []):
                deps.append({
                    "source": source,
                    "target": child
                })
        return {"refs": refs, "deps": deps}
    
    except Exception as e:
        print(f"[ERROR] Fallimento estrazione grafo: {e}")
        return {"refs": [], "deps": []}


# ============================================================
# CREAZIONE DI UN ALBERO/GRAFO PER IL DOCKER CHE E' FLAT -> UNIFICA TUTTE LE DIPENDENZE IN UN'UNICA STRUTTURA GERARCHICA
# ============================================================
def build_universal_hierarchy(name_sbom_file_docker: str, folder_path: str):
    
    all_dependencies_data = {}
    
    # Raccolta dei file
    search_paths = [os.path.join(folder_path, d) for d in ["manifests", "dependencies"] 
                    if os.path.exists(os.path.join(folder_path, d))]
    
    for path in search_paths:
        for file_name in os.listdir(path):
            if file_name.endswith(".json"):
                file_path = os.path.join(path, file_name)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        all_dependencies_data[file_name] = get_all_dependecies(f.read())
                except Exception as e:
                    print(f"[ERROR] Impossibile elaborare {file_name}: {e}")

    # Conversione "Grafo -> Mappa" (La traduzione necessaria)
    unified_map = {}
    for filename, data in all_dependencies_data.items():
        for edge in data.get("deps", []):
            source = edge.get("source")
            target = edge.get("target")
            if source not in unified_map:
                unified_map[source] = {"dependencies": []}
            if target not in unified_map[source]["dependencies"]:
                unified_map[source]["dependencies"].append(target)

    # Costruzione della Gerarchia Universale
    with open(os.path.join(STORAGE_DIR, name_sbom_file_docker), "r") as f:
        trivy_data = json.load(f)
        sbom_components = trivy_data.get("components", [])
    
    hierarchy = {}
    for comp in sbom_components:
        purl = comp.get('purl')
        if not purl: continue
        # Colleghiamo il PURL alla sua lista di figli trovata nella unified_map
        hierarchy[purl] = unified_map.get(purl, {}).get('dependencies', [])

    for comp in sbom_components:
        purl = comp.get('purl')
        if purl and purl not in hierarchy:
            hierarchy[purl] = []
            
    return hierarchy

# ============================================================
# FUNZIONE DI SUPPORTO PER CALCOLARE IL PESO DI UNA DIPENDENZA (numero totale di dipendenze dirette e indirette)
# ============================================================

def get_dependency_weight(purl, hierarchy, memo=None):
    if memo is None: memo = {} # memo è un dizionario per memorizzare i risultati già calcolati
    if purl in memo: return memo[purl] # Se il peso è già stato calcolato, ritorna il valore memorizzato
    
    # Prendi le dipendenze dirette
    children = hierarchy.get(purl, [])
    total = len(children)
    
    # Somma ricorsivamente le dipendenze dei figli
    for child in children:
        total += get_dependency_weight(child, hierarchy, memo)
        
    memo[purl] = total
    return total

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
                # Estrai il file temporaneamente
                zip_ref.extract(file_name, dest_dir)
                file_path = os.path.join(dest_dir, file_name)
                
                # Smista in base al nome
                if "requirements" in file_name or "poetry" in file_name:
                    shutil.move(file_path, os.path.join(manifests_dir, file_name))
                elif file_name != "docker_sbom.json" and file_name != "cyclonedx-license-SBOM.json" and file_name != "cyclonedx-vuln-SBOM.json":
                    shutil.move(file_path, os.path.join(deps_dir, file_name))
    
    # Rimuovi lo zip dopo aver estratto
    if os.path.exists(zip_path):
        os.remove(zip_path)
        
    return True

# ============================================================
# TRIGGER GITHUB ACTION per avviare pipeline remote specifiche e recuperare URL e ID della run
# ============================================================

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
# Gestore per rimuovere file in sola lettura durante la pulizia della cartella di storage
# ============================================================
    
def remove_readonly(func, path, excinfo):
    os.chmod(path, stat.S_IWRITE)
    func(path)

# ============================================================
# ACQUISIZIONE E SALVATAGGIO IN MEMORIA SERVER di file JSON manuali o generati
# ============================================================

@app.post("/upload-sbom")
async def upload_sbom(
    action: str = Form(...),
    mode: str = Form("manual"), # Default manuale
    repo_url: Optional[str] = Form(None), # Necessario per clonare
    branch: Optional[str] = Form(None), # Necessario per clonare
    requirements_file: Optional[UploadFile] = File(None),
    poetry_file: Optional[UploadFile] = File(None),
    docker_file: Optional[UploadFile] = File(None),
):
    # pulizia della cartella di storage per evitare conflitti con file precedenti
    if os.path.exists(STORAGE_DIR):
        shutil.rmtree(STORAGE_DIR, onerror=remove_readonly)
    os.makedirs(STORAGE_DIR, exist_ok=True)
    
    # Se il mode è "docker", eseguiamo il discovery automatico dei file di dipendenze dal Dockerfile
    if mode == "docker":
        if not repo_url:
            raise HTTPException(400, "URL repository mancante per il discovery.")
            
        tmp_clone = tempfile.mkdtemp()
        try:
            subprocess.run(["git", "clone", "--depth", "1", "--branch", branch, repo_url, tmp_clone], check=True)
            
            # Parsing dei file
            found_files = []
            valid_patterns = ["requirements.txt", "pyproject.toml", "poetry.lock", "dependencies.json", "package.json"]
            
            for root, _, files in os.walk(tmp_clone):
                for f in files:
                    if f in valid_patterns:
                        file_path = os.path.join(root, f)
                        dest_path = os.path.join(STORAGE_DIR, f)
                        shutil.copy(file_path, dest_path)
                        found_files.append(f)
            
            if not found_files:
                raise HTTPException(400, "Nessun file di dipendenze rilevato.")
            
            with open(os.path.join(STORAGE_DIR, "discovered_files.json"), "w") as f:
                json.dump(found_files, f)
            
            return {"status": "success", "files": found_files}
            
        finally:
            shutil.rmtree(tmp_clone, onerror=remove_readonly)
            
    # Se l'azione è "upload", salviamo tutti i file manuali caricati (requirements, poetry, docker) per l'analisi comparativa
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

    # Se l'azione è "generate", salviamo solo il file Docker (se presente) e prepariamo il server per la pipeline remota
    elif action == "generate":
        if docker_file:
            with open(os.path.join(STORAGE_DIR, "docker_sbom.json"), "wb") as f:
                f.write(await docker_file.read())
        return {"status": "success", "message": "Pronto per l'attivazione della pipeline di generazione remota."}

# ============================================================
# Recupero dei file scoperti durante la fase di discovery per visualizzazione nel frontend
# ============================================================

@app.get("/get-discovered-files")
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
@app.post("/analyze-standard-file")
async def analyze_standard_file(
    format: str = Form(...), 
    repo_url: str = Form(...),
    branch: str = Form(...)
):
    # Logica per gestire "Entrambi"
    files_da_analizzare = []
    if format == "Entrambi":
        files_da_analizzare = ["requirements", "poetry"] # Aggiungi quelli che vuoi
    else:
        if format not in ["requirements", "poetry", "pyproject.toml", "poetry.lock"]:
            raise HTTPException(status_code=400, detail="Formato non supportato per l'analisi standard.")
        elif format == "requirements.txt":
            files_da_analizzare = ["requirements"]
        elif format == "pyproject.toml" or format == "poetry.lock":
            files_da_analizzare = ["poetry"]

    results = []
    
    # Eseguiamo l'analisi per ogni file richiesto
    for f_name in files_da_analizzare:
        try:
            # Chiamiamo la funzione che esegue la Action e scarica l'artefatto
            risultato = run_standard_sbom_action(repo_url, branch, f_name)
            results.append(risultato)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Errore durante l'analisi di {f_name}: {str(e)}")

    # Ritorna la lista dei risultati
    return {"status": "success", "data": results, "type": "standard"}

# ============================================================
# FUNZIONE DI SUPPORTO
# ============================================================

def run_standard_sbom_action(repo_url, branch, format):
    
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
        "pyproject": "trivy_pyproject.json"
    }

    if format not in mapping:
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

# ============================================================
# LOGICA 2: ANALISI AVANZATA (Solo per dependencies.json)
# ============================================================
@app.post("/analyze-custom-file")
def analyze_custom_file(
    repo_url: str = Form(...), 
    branch: str = Form(...), 
    path_file: str = Form(...)
):
    tmp_clone = tempfile.mkdtemp() # Creiamo una cartella temporanea per il clone del repository
    
    try:
    
    # Clone leggero del repository per estrarre il file dipendenze custom
        subprocess.run([
            "git", "clone", "--depth", "1", "--branch", branch, repo_url, tmp_clone
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        target_file = None
        for root, _, files in os.walk(tmp_clone):
            if path_file in files:
                target_file = os.path.join(root, path_file)
                break

        if not target_file:
            raise HTTPException(404, f"File '{path_file}' non trovato nella repository.")

        with open(target_file, "r", encoding="utf-8") as f:
            dependencies = json.load(f)

        if not isinstance(dependencies, list):
            raise HTTPException(400, "Il file delle dipendenze deve essere una lista JSON.")
        
        # Funzione di utilità per estrarre identificatori dai file JSON generati
        def extract_names_and_purls(file_path):
            names = set()
            purls = set()
            if not os.path.exists(file_path):
                return names, purls
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
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
                        purl = item.get("purl")
                        if name: names.add(str(name).lower().strip())
                        if purl: purls.add(str(purl).lower().strip())
                    elif isinstance(item, str):
                        names.add(item.lower().strip())
                return names, purls
            except Exception:
                return names, purls

        # Carichiamo gli identificatori reali per la mappatura delle colonne nella tabella
        req_identifiers, _ = extract_names_and_purls(os.path.join(STORAGE_DIR, "trivy_requirements.json"))
        poetry_identifiers, _ = extract_names_and_purls(os.path.join(STORAGE_DIR, "trivy_poetry.json"))

        extracted_data = []
        repos = []

        # Analizziamo e integriamo la lista dipendenze del repository Git
        for item in dependencies:
            dep_type = item.get("type", "N/A")
            name, version, purl = extract(item)
            component_type = classify(dep_type)
            github_repo = parse_github_url(item.get("url", ""))

            if github_repo != "N/A":
                repos.append(github_repo)

            name_clean = str(name).lower().strip()

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


        return {
            "status": "success",
            "repo": repo_url,
            "branch": branch,
            "count": len(extracted_data),
            "result": extracted_data,
            "detected_git_repos": list(set(repos))
        }

    except Exception as e:
        print(f"[CRITICAL ERROR] Fallimento catastrofico in compare_dependencies: {str(e)}", flush=True)
        raise HTTPException(500, f"Errore interno del server: {str(e)}")
    finally:
        shutil.rmtree(tmp_clone, ignore_errors=True)
        
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# IN CASO MODIFICARE QUESTA FUNZIONE PER AGGIUNGERE NUOVI TIPI DI FILE O FORMATI DI DIPENDENZE
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# ============================================================
# ANALISI COMPONENTI DEPENDENCIES.JSON IN PARALLELO (con github action remota) e generazione SBOM per singole dipendenze
# ============================================================

@app.post("/analyze-dependencies-sbom")
def analyze_dependencies_sbom(
    repo_url: str = Form(...), 
    branch: str = Form(...), 
    path_file: str = Form(...)
):
    workflow_name = "dynamic_sbom.yml"
    print(f"[BACKEND] Avvio pipeline avanzata per singole dipendenze...", flush=True)
    print(f"[DEBUG] Parametri analisi dipendenze: repo_url={repo_url}, branch={branch}, path_dipendenze={path_file}", flush=True)
    
    match = re.search(r"github\.com/([^/]+)/([^/?#]+)", repo_url)
    owner_repo = f"{match.group(1)}/{match.group(2).replace('.git', '')}" if match else repo_url
    
    inputs = {
        "src_repository": owner_repo,
        "src_branch": branch,
        "path_dipendenze": path_file
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
    
    # Definizione delle cartelle da scansionare
    folders_to_scan = [
        os.path.join(STORAGE_DIR, "manifests"),
        os.path.join(STORAGE_DIR, "dependencies")
    ]
    
    # Scansione dei file SBOM generati e caricamento in memoria per la visualizzazione
    for folder in folders_to_scan:
        if os.path.exists(folder):
            for file_name in os.listdir(folder):
                if file_name.endswith("-sbom.json"):
                    
                    file_path = os.path.join(folder, file_name)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            # Usiamo il path relativo o il nome come chiave
                            generated_sboms[file_name] = f.read()
                        print(f"[BACKEND] Caricato con successo: {file_name}", flush=True)
                    except Exception as e:
                        print(f"[BACKEND] Errore nella lettura {file_path}: {str(e)}", flush=True)
    
    # Generazione dei dati per la visualizzazione del grafo
    graph_results = {}
    graph_results.update(generate_graphs_for_folder(os.path.join(STORAGE_DIR, "manifests")))
    graph_results.update(generate_graphs_for_folder(os.path.join(STORAGE_DIR, "dependencies")))
   
    return {
        "status": "success",
        "github_run_url": github_run_url,
        "sboms": generated_sboms,
        "graphs": graph_results
    }

# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# IN CASO MODIFICARE QUESTA FUNZIONE PER AGGIUNGERE NUOVI TIPI DI FILE O FORMATI DI DIPENDENZE
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

# ============================================================
# GENERAZIONE SBOM DOCKER REMOTA e ANALISI COMPARATIVA IMMEDIATA
# ============================================================

@app.post("/generate-docker-sbom")
def generate_docker_sbom(docker_target: str, vuln_type: str = "os,library"):
    
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
        weight = get_dependency_weight(purl, docker_graph_results, memo)
        hierarchy_with_weights[purl] = {
            "dependencies": docker_graph_results[purl],
            "weight": weight
        }
    
    
    def get_global_code_map():
        #Restituisce: { purl: [ {file: 'nomefile.json', name: '...', version: '...'}, ... ] }
        global_map = {}
        target_dirs = [os.path.join(STORAGE_DIR, "manifests"), os.path.join(STORAGE_DIR, "dependencies")]
        ignore_files = {"docker_sbom.json", "cyclonedx-vuln-SBOM.json", "cyclonedx-license-SBOM.json"}
        
        for folder in target_dirs:
            if os.path.exists(folder):
                for root, _, files in os.walk(folder):
                    for file_name in files:
                        if file_name.endswith(".json") and file_name not in ignore_files:
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
    
    all_code_names_only = {entry["name"].lower().strip() for entries in code_map.values() for entry in entries if entry.get("name")}
    
    docker_components_unique = {f"{c['name'].lower().strip()}@{c['version']}": c for c in docker_components}.values()
    # CONFRONTO OTTIMIZZATO
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
    in_common = sorted(in_common, key=lambda x: x["name"].lower())
    only_in_docker = sorted(only_in_docker, key=lambda x: x["name"].lower())
    version_mismatches = sorted(version_mismatches, key=lambda x: x["docker"]["name"].lower())
    
    
    # --- Analisi separata per le dipendenze che ci sono nel sorgente ma non nel docker SBOM ---
    docker_purl_set = {dc["purl"].lower().strip() for dc in docker_components if dc.get("purl")}
    missing_in_docker = []

    for purl, entries in code_map.items():
        if purl not in docker_purl_set:
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)