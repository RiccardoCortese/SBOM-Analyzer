import os
import json
import re
from dockerfile_parse import DockerfileParser
from docker_analysis.docker_step_analyzer import DockerStepAnalyzer
from docker_analysis.docker_step_builder import DockerStepBuilder
from docker_analysis.docker_image_analyzer import DockerImageAnalyzer
from docker_analysis.sbom_diff import compare_sbom
from docker_analysis.docker_artifact_detector import DockerArtifactDetector
from config import STORAGE_DIR

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
            if "vuln" in file_name or "license" in file_name or file_name == "discovered_files.json":
                continue  # Ignora file di vulnerabilità e licenze
            else:
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
        
        # Creiamo una mappa di risoluzione: UUID/ref -> PURL/Name
        # Questo permette di tradurre "572ec16b..." in un nome leggibile
        ref_map = {}
        for comp in data.get("components", []):
            ref_id = comp.get("bom-ref")
            # Usiamo il purl se esiste, altrimenti il nome
            display_name = comp.get("purl") or comp.get("name")
            if ref_id:
                # Crezione della mappa solo se abbiamo un ref_id valido
                ref_map[ref_id] = display_name
        
        deps = []
        # Estrazione Dipendenze con risoluzione
        dependencies = data.get("dependencies", [])
        for dep in dependencies:
            # Estraiamo la sorgente (ref) e traduciamo in nome leggibile se possibile
            raw_source = dep.get("ref")
            # Traduciamo la sorgente (se è un UUID, cerchiamo il suo PURL/nome)
            source = ref_map.get(raw_source, raw_source)
            
            for child in dep.get("dependsOn", []):
                # Traduciamo il target (se è un UUID, cerchiamo il suo PURL/nome)
                target = ref_map.get(child, child)
                deps.append({
                    "source": source,
                    "target": target
                })
        
        return {"deps": deps}
    
    except Exception as e:
        print(f"[ERROR] Fallimento estrazione grafo: {e}")
        return {"deps": []}

# ============================================================
# CREAZIONE DI UN ALBERO/GRAFO PER IL DOCKER CHE E' FLAT -> UNIFICA TUTTE LE DIPENDENZE IN UN'UNICA STRUTTURA GERARCHICA
# ============================================================
def build_universal_hierarchy(name_sbom_file_docker: str, folder_path: str):
    
    all_dependencies_data = {}
    
    # Raccolta dei file
    #search_paths = [os.path.join(folder_path, d) for d in ["manifests", "dependencies"] 
    #                if os.path.exists(os.path.join(folder_path, d))]
    
    # Analizziamo tutti i file JSON trovati nelle cartelle specificate
    #for path in search_paths:
    for file_name in os.listdir(folder_path):
        if file_name == "final_merged_sbom.json":
            file_path = os.path.join(folder_path, file_name)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    all_dependencies_data[file_name] = get_all_dependecies(f.read())
            except Exception as e:
                print(f"[ERROR] Impossibile elaborare {file_name}: {e}")
                    

    # Conversione in un'unica mappa di dipendenze per facilitare la costruzione della gerarchia totale
    unified_map = {}
    for filename, data in all_dependencies_data.items():
        for edge in data.get("deps", []):
            source = edge.get("source")
            target = edge.get("target")
            if source not in unified_map:
                unified_map[source] = {"dependencies": []}
            if target not in unified_map[source]["dependencies"]:
                unified_map[source]["dependencies"].append(target)

    # Costruzione della gerarchia totale 
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

def get_dependency_weight(purl, hierarchy, memo=None, visited_global=None):
    if memo is None: memo = {} # memo è un dizionario per memorizzare i risultati già calcolati
    if purl in memo: return memo[purl] # Se il peso è già stato calcolato, ritorna il valore memorizzato
    
    # Protezione dai cicli
    if visited_global is None: visited_global = set()
    if purl in visited_global: return 0, set(), 0
    visited_global.add(purl)
    
    count_total = 0 # totale delle dipendenze (dirette e indirette)
    unique_nodes = set() # insieme dei nodi unici visitati per calcolare l'overlap
    
    children = hierarchy.get(purl, []) # Recupera i figli della dipendenza corrente dalla gerarchia
    
    for child in children:
        # Aggiungiamo il figlio stesso
        count_total += 1
        unique_nodes.add(child)
        
        # Chiamata ricorsiva
        child_total, child_unique, child_overlap = get_dependency_weight(child, hierarchy, memo, visited_global)
        
        count_total += child_total
        unique_nodes.update(child_unique)
    
    # Calcolo overlap: (Nodi totali visitati nella ricorsione) - (Nodi univoci)
    overlap = count_total - len(unique_nodes)
    
    # Memorizziamo sia il totale che l'insieme dei nodi univoci
    memo[purl] = (count_total, unique_nodes, overlap)
    
    # Backtracking: rimuoviamo dal set dei nodi visitati nel path corrente
    visited_global.remove(purl)
    
    return count_total, unique_nodes, overlap

# ===========================================================
#  Funzioni per il Dockerfile Parser e l'analisi dei RUN
# ===========================================================

# Funzione per estrarre tutte le immagini di base da un Dockerfile, per 
def extract_base_images(dockerfile_content):
    parser = DockerfileParser()
    parser.content = dockerfile_content

    images = []

    for inst in parser.structure:
        instruction = inst["instruction"].upper()
        value = inst["value"]

        if instruction == "FROM":
            if "ghcr.io/" in value or "docker.io/" in value or "quay.io/" in value or "registry.gitlab.com/" in value:
                images.append(value)

    return images

# Funzione per analizzare un Dockerfile e restituire gli step
def get_docker_analysis(dockerfile_content,  build_context):

    # Analisi del Dockerfile per estrarre gli step e le immagini di base
    # Uno step è rappresentato da un'istruzione RUN, COPY, ADD, ecc. e viene costruito un Dockerfile progressivo per ogni step
    analyzer = DockerStepAnalyzer(dockerfile_content)

    steps = analyzer.parse()
    
    # Analisi dei RUN per estrarre i candidati a artefatti (file copiati, pacchetti installati, ecc.), per possibili vulnerabilità
    artifact_detector = DockerArtifactDetector()
    
    artifacts = artifact_detector.analyze(steps)
    print (f"Artefatti rilevati: {len(artifacts)}")
    print (f"Artefatti: {artifacts}")
    
    # Estrazioni delle immagini dal FROM del docker
    images = extract_base_images(dockerfile_content)

    # Costruzione delle immagini intermedie per ogni step e salvataggio dei tag
    builder = DockerStepBuilder(
        build_context=build_context
    )
    
    os.makedirs(os.path.join(STORAGE_DIR, "docker_sbom_steps"), exist_ok=True)
    # Creazione di un'istanza di DockerImageAnalyzer per generare SBOM per ogni immagine intermedia
    image_analyzer = DockerImageAnalyzer(output_dir=os.path.join(STORAGE_DIR, "docker_sbom_steps"))

    try:
        
        sbom_paths = []
        
        for step in steps:

            image = builder.build(step)

            print( "Creata immagine:", image )

            # salvo il riferimento nello step
            step.image_tag = image
            
            # genera SBOM
            sbom_path = image_analyzer.generate_sbom( image, step.index)

            print(f"SBOM generato: {sbom_path}")

            # salvo riferimento nello step
            step.sbom_path = sbom_path
            
            sbom_paths.append(sbom_path)
            
            # Caricamento SBOM
            sbom = image_analyzer.load_sbom(sbom_path)

            unique_components = {comp.get("name") for comp in sbom.get("components", []) if comp.get("name")}
        
            step.total_components = len(unique_components)
            print(f"Step {step.index}:", step.total_components, "componenti unici")
            
        diffs = []

        for i in range(1, len(sbom_paths)):

            diff = compare_sbom(sbom_paths[i-1], sbom_paths[i]) # compara SBOM tra step i-1 e i


            diffs.append({
                    "from": i-1,
                    "to": i,
                    "diff": diff
                }
            )

    finally:

        builder.cleanup()
    
    return {
    "steps": [
        {
            "index": step.index,
            "dockerfile_content": step.dockerfile_content,
            "image_tag": step.image_tag,
            "sbom_path": step.sbom_path,
            "total_components": step.total_components
        }
        for step in steps
    ],
    "images": images,
    "diffs": diffs,
    "artifacts": [
        {
            "step_index": artifact.step_index,
            "artifact_type": artifact.artifact_type,
            "source": artifact.source,
            "destination": artifact.destination,
            "reason": artifact.reason,
            "source_type": artifact.source_type
        }
        for artifact in artifacts
    ]
}
    