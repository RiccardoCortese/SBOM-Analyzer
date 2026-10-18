import os
import json
import re
import shutil
import requests
from urllib.parse import quote
from packageurl import PackageURL
from dockerfile_parse import DockerfileParser
from docker_analysis.docker_step_analyzer import DockerStepAnalyzer
from docker_analysis.docker_step_builder import DockerStepBuilder
from docker_analysis.docker_image_analyzer import DockerImageAnalyzer
from docker_analysis.sbom_diff import compare_sbom
from docker_analysis.docker_artifact_detector import DockerArtifactDetector
from docker_analysis.docker_filesystem_extraxtor import DockerFilesystemExtractor
from security.yara_scanner import YaraScanner
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

    merged_path = os.path.join(folder_path, "final_merged_sbom.json")

    if os.path.exists(merged_path):
        try:
            with open(merged_path, "r", encoding="utf-8") as f:
                all_dependencies_data["final_merged_sbom.json"] = (
                    get_all_dependecies(f.read())
                )
        except Exception as e:
            print(f"[ERROR] Impossibile elaborare final_merged_sbom.json: {e}")

    sbom_path = os.path.join(STORAGE_DIR, name_sbom_file_docker)

    with open(sbom_path, "r", encoding="utf-8") as f:
        trivy_data = json.load(f)

    components = trivy_data.get("components", [])

    # PURL dei soli componenti presenti nello SBOM Docker.
    docker_purls = {
        comp.get("purl")
        for comp in components
        if isinstance(comp, dict) and comp.get("purl")
    }

    unified_map = {}

    for data in all_dependencies_data.values():
        for edge in data.get("deps", []):
            source = edge.get("source")
            target = edge.get("target")

            # Entrambi gli estremi devono essere nell'immagine Docker.
            if source not in docker_purls or target not in docker_purls:
                continue

            unified_map.setdefault(source, [])

            if target not in unified_map[source]:
                unified_map[source].append(target)

    # Mantiene tutti i nodi Docker, anche quelli senza archi.
    hierarchy = {
        purl: unified_map.get(purl, [])
        for purl in docker_purls
    }

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
# FUNZIONE DI SUPPORTO CHE CHIAMA L'API DEPS.DEV PER RECUPERARE LE DIPENDENZE DI UN PACCHETTO, UTILIZZANDO IL PURL COME IDENTIFICATORE
# ===========================================================

DEPS_DEV_SYSTEMS = {
    "maven": "maven",
    "pypi": "pypi",
    "npm": "npm",
    "cargo": "cargo",
}


def dependency_identity(purl):
    """Converte un PURL in un'identità confrontabile con deps.dev."""
    try:
        parsed = PackageURL.from_string(purl)
    except Exception:
        return None

    package_type = (parsed.type or "").lower()

    if package_type not in DEPS_DEV_SYSTEMS:
        return None

    if not parsed.name or not parsed.version:
        return None

    namespace = parsed.namespace or ""
    name = parsed.name
    version = parsed.version

    if package_type == "maven":
        # deps.dev identifica Maven con groupId:artifactId.
        package_name = f"{namespace}:{name}" if namespace else name
        normalized_name = package_name
    elif package_type == "npm" and namespace:
        normalized_name = f"{namespace}/{name}".lower()
    elif package_type in {"pypi", "cargo", "npm"}:
        normalized_name = name.lower()
    else:
        normalized_name = name

    return (
        DEPS_DEV_SYSTEMS[package_type],
        normalized_name,
        version,
    )


def fetch_deps_dev_dependencies(identity, session, cache):
    """
    Restituisce le identità delle dipendenze dichiarate da deps.dev.
    Le identità vengono poi filtrate rispetto ai componenti Docker.
    """
    if identity in cache:
        return cache[identity]

    system, package_name, version = identity

    # Codifica i segmenti del percorso senza codificare i separatori
    # strutturali dell'endpoint.
    encoded_package = quote(package_name, safe=":@")
    encoded_version = quote(version, safe="")

    url = (
        f"https://api.deps.dev/v3alpha/systems/{system}"
        f"/packages/{encoded_package}"
        f"/versions/{encoded_version}:dependencies"
    )

    try:
        response = session.get(url, timeout=15)

        if response.status_code != 200:
            print(
                f"[DEPS.DEV] HTTP {response.status_code} "
                f"per {system}:{package_name}@{version}"
            )
            cache[identity] = []
            return []

        data = response.json()
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])

        # Gli archi dell'API usano indici nella lista nodes.
        node_identities = []

        for node in nodes:
            version_key = node.get("versionKey", {})

            node_system = (version_key.get("system") or "").lower()
            node_name = version_key.get("name", "")
            node_version = version_key.get("version", "")

            if not node_system or not node_name or not node_version:
                node_identities.append(None)
                continue

            if node_system == "maven":
                normalized_name = node_name
            elif node_system in {"pypi", "npm", "cargo"}:
                normalized_name = node_name.lower()
            else:
                normalized_name = node_name

            node_identities.append(
                (node_system, normalized_name, node_version)
            )

        result = []

        for edge in edges:
            source_index = edge.get("fromNode")
            target_index = edge.get("toNode")

            if not isinstance(source_index, int):
                continue

            if not isinstance(target_index, int):
                continue

            if not (
                0 <= source_index < len(node_identities)
                and 0 <= target_index < len(node_identities)
            ):
                continue

            source_identity = node_identities[source_index]
            target_identity = node_identities[target_index]

            if source_identity is None or target_identity is None:
                continue

            # Conserva solo gli archi in uscita dal pacchetto interrogato.
            if source_identity == identity:
                result.append(target_identity)

        cache[identity] = list(set(result))
        return cache[identity]

    except Exception as e:
        print(
            f"[DEPS.DEV] Errore per {system}:{package_name}@{version}: {e}"
        )
        cache[identity] = []
        return []


def complete_graph_with_deps_dev(hierarchy, docker_sbom_path):
    """
    Completa gli archi mancanti senza aggiungere nodi.

    Ritorna:
      - hierarchy completato
      - lista degli archi aggiunti tramite deps.dev
    """
    with open(docker_sbom_path, "r", encoding="utf-8") as f:
        sbom_data = json.load(f)

    components = [
        comp
        for comp in sbom_data.get("components", [])
        if isinstance(comp, dict) and comp.get("purl")
    ]

    # Identità deps.dev -> PURL originale Docker.
    identity_to_purl = {}

    for component in components:
        purl = component["purl"]
        identity = dependency_identity(purl)

        if identity is not None:
            identity_to_purl.setdefault(identity, purl)

    docker_purls = set(hierarchy)

    # Elimina eventuali archi preesistenti che puntano fuori dallo SBOM.
    for source in hierarchy:
        hierarchy[source] = list(dict.fromkeys(
            target
            for target in hierarchy[source]
            if target in docker_purls
        ))

    # L'API viene interrogata per nodi senza dipendenze in uscita.
    candidates = [
        purl
        for purl in hierarchy
        if not hierarchy[purl]
        and dependency_identity(purl) is not None
    ]

    deps_dev_edges = []
    cache = {}
    session = requests.Session()

    try:
        for source_purl in candidates:
            source_identity = dependency_identity(source_purl)

            if source_identity is None:
                continue

            discovered = fetch_deps_dev_dependencies(
                source_identity,
                session,
                cache,
            )

            for target_identity in discovered:
                # Non creare nodi che non esistono nello SBOM Docker.
                target_purl = identity_to_purl.get(target_identity)

                if target_purl is None:
                    continue

                if target_purl not in docker_purls:
                    continue

                if target_purl == source_purl:
                    continue

                # Registra soltanto gli archi realmente nuovi.
                if target_purl not in hierarchy[source_purl]:
                    hierarchy[source_purl].append(target_purl)

                    deps_dev_edges.append({
                        "source": source_purl,
                        "target": target_purl,
                    })
    finally:
        session.close()

    print(
        f"[DEPS.DEV] Componenti interrogati: {len(candidates)}; "
        f"archi aggiunti: {len(deps_dev_edges)}"
    )

    return hierarchy, deps_dev_edges
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

def get_docker_analysis(dockerfile_content, build_context):
    
    # Analisi Dockerfile
    analyzer = DockerStepAnalyzer(dockerfile_content)

    steps = analyzer.parse()

    # Individuazione possibili artefatti
    artifact_detector = DockerArtifactDetector()

    artifacts = artifact_detector.analyze(steps)

    # Estrazione immagini base
    images = extract_base_images(dockerfile_content)
    
    # Builder immagini intermedie
    builder = DockerStepBuilder(build_context=build_context)

    filesystem_extractor = DockerFilesystemExtractor()

    yara_scanner = YaraScanner(
        "security/yara_rules/reversinglabs-yara-rules/yara"
    )

    all_yara_results = []

    os.makedirs(os.path.join(STORAGE_DIR, "docker_sbom_steps"), exist_ok=True)

    image_analyzer = DockerImageAnalyzer(output_dir=os.path.join(STORAGE_DIR, "docker_sbom_steps"))

    try:

        sbom_paths = []
        previous_filesystem = None
        filesystem_path = None
        #steps = steps[:4]
        for step in steps:

            # Costruzione immagine dello step
            image = builder.build(step)

            print("Creata immagine:", image)

            step.image_tag = image
            
            if any(artifact.step_index == step.index for artifact in artifacts):
                
                print(f"[WARNING] Possibili artefatti rilevati nello step {step.index}")
                
                # ==========================
                # YARA ANALYSIS, se si vuole analisi decommentare qui
                # ==========================
                """
                filesystem_path = filesystem_extractor.extract(image)

                try:
                    if previous_filesystem:

                        new_files = filesystem_extractor.get_new_files(
                            previous_filesystem,
                            filesystem_path
                        )

                        print(
                            f"[YARA] Step {step.index}: {len(new_files)} nuovi file"
                        )

                        step_yara_results = yara_scanner.scan_files(
                            filesystem_path,
                            new_files
                        )

                    else:
                        new_files = filesystem_extractor.list_files(
                            filesystem_path
                        )

                        step_yara_results = yara_scanner.scan_files(
                            filesystem_path,
                            new_files
                        )
                finally:
                    
                    previous_filesystem = filesystem_path
                    
                    if filesystem_path:
                        shutil.rmtree(
                            os.path.dirname(filesystem_path),
                            ignore_errors=True
                        )

                step.yara_results = step_yara_results

                all_yara_results.append(
                    {
                        "step": step.index,
                        "image": image,
                        "matches": step_yara_results
                    }
                )

                print(f"[YARA] Step {step.index} - Risultati YARA: {len(step_yara_results)} match trovati")
                if step_yara_results:

                    print("[WARNING] Possibile Malware trovato nello step",step.index)

                    print(step_yara_results)"""
                    
                
            # voglio all_yara_results vuoto   
            all_yara_results.append(
                {
                    "step": step.index,
                    "image": image,
                    "matches": [],
                    "valid": False
                }
            )
            
            
                      
            # ==========================
            # SBOM ANALYSIS
            # ==========================

            sbom_path = image_analyzer.generate_sbom(
                image,
                step.index
            )

            print(f"SBOM generato: {sbom_path}")

            step.sbom_path = sbom_path

            sbom_paths.append(sbom_path)

            sbom = image_analyzer.load_sbom(sbom_path)

            unique_components = {
                comp.get("purl")
                for comp in sbom.get("components", [])
                if comp.get("purl")
            }

            step.total_components = len(unique_components)

            print( f"Step {step.index}:", step.total_components, "componenti unici" )

        
        # ==========================
        # SBOM DIFF
        # ==========================

        diffs = []
        removed_components = {}

        for i in range(1, len(sbom_paths)):

            diff = compare_sbom(
                sbom_paths[i-1],
                sbom_paths[i]
            )

            diffs.append(
                {
                    "from": i-1,
                    "to": i,
                    "diff": diff
                }
            )

            # Accumula le librerie rimosse
            for comp in diff.get("removed", []):
                purl = comp.get("purl")

                if purl:
                    removed_components[purl] = comp

            # Rimuove dal registro le librerie reintrodotte
            for comp in diff.get("added", []):
                purl = comp.get("purl")

                if purl:
                    removed_components.pop(purl, None)

        # Converte il dizionario in una lista
        removed_components = list(removed_components.values())



    finally:
        if filesystem_path:
            shutil.rmtree(
                os.path.dirname(filesystem_path),
                ignore_errors=True
            )

        builder.cleanup()

    return {
        "steps": [
            {
                "index": step.index,
                "dockerfile_content": step.dockerfile_content,
                "image_tag": step.image_tag,
                "sbom_path": step.sbom_path,
                "total_components": step.total_components,
                "yara_results": step.yara_results
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
        ],
        "yara": all_yara_results,
        "removed_components": removed_components
    }