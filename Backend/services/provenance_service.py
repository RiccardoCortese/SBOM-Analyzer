import json
import os
import glob
import re


# Carica un file SBOM in formato JSON.
# Se il file non esiste, non è valido o non contiene un oggetto JSON,
# restituisce None.
def load_sbom_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            return None

        return data

    except Exception as e:
        print(f"[PROVENANCE] Errore lettura {file_path}: {e}", flush=True)
        return None


# Estrae i componenti presenti in uno SBOM e li organizza utilizzando il PURL del componente come chiave.

def get_components_from_sbom(sbom):
    components = {}

    for component in sbom.get("components", []):
        if not isinstance(component, dict):
            continue

        purl = component.get("purl")

        if not purl:
            continue

        components[purl] = component

    return components

# Crea una mappa tra il bom-ref CycloneDX e il PURL del componente.
# Serve per collegare le relazioni di dipendenza al componente corretto.
def get_bom_ref_to_purl(sbom):
    mapping = {}

    for component in sbom.get("components", []):
        if not isinstance(component, dict):
            continue

        purl = component.get("purl")
        bom_ref = component.get("bom-ref")

        if not purl:
            continue

        # Il bom-ref può essere un UUID
        if bom_ref:
            mapping[bom_ref] = purl

        # In alcuni SBOM il riferimento può essere direttamente il PURL
        mapping[purl] = purl

    return mapping

# Costruisce una mappa PURL -> componenti da cui dipende direttamente.
# Le relazioni vengono lette dalla sezione "dependencies" dello SBOM.

def get_component_dependencies(sbom):
    dependencies = {}

    bom_ref_to_purl = get_bom_ref_to_purl(sbom)

    for dependency in sbom.get("dependencies", []):
        if not isinstance(dependency, dict):
            continue

        ref = dependency.get("ref")

        if not ref:
            continue

        parent_purl = bom_ref_to_purl.get(ref)

        if not parent_purl:
            continue

        child_purls = []

        for child_ref in dependency.get("dependsOn", []):
            child_purl = bom_ref_to_purl.get(child_ref)

            if child_purl:
                child_purls.append(child_purl)

        dependencies[parent_purl] = child_purls

    return dependencies


# Cerca ricorsivamente il percorso di dipendenze che porta da un componente principale fino al componente target.
# Esempio:
# paperless-ngx -> requests -> urllib3
def find_dependency_chain(target_purl, dependencies):

    def search(current_purl, path, visited):

        if current_purl in visited:
            return None

        visited.add(current_purl)
        path = path + [current_purl]

        if current_purl == target_purl:
            return path

        for child_purl in dependencies.get(current_purl, []):
            result = search(child_purl, path, visited.copy())

            if result:
                return result

        return None

    for root_purl in dependencies:

        result = search(root_purl, [], set())

        if result:
            return result

    return None

# Carica tutti gli SBOM generati durante i vari step del Dockerfile.
# I file vengono ordinati in base al numero dello step, ad esempio:
# step_1_sbom.json, step_2_sbom.json, step_3_sbom.json, ...
def load_docker_step_sboms(STORAGE_DIR):
    steps = []

    steps_dir = os.path.join(STORAGE_DIR, "docker_sbom_steps")

    if not os.path.exists(steps_dir):
        return steps

    files = glob.glob(os.path.join(steps_dir, "step_*_sbom.json"))

    def step_number(path):
        match = re.search(
            r"step_(\d+)_sbom\.json",
            os.path.basename(path)
        )

        return int(match.group(1)) if match else 999999

    files.sort(key=step_number)

    for file_path in files:

        sbom = load_sbom_file(file_path)

        if not sbom:
            continue

        match = re.search(
            r"step_(\d+)_sbom\.json",
            os.path.basename(file_path)
        )

        if not match:
            continue

        step_index = int(match.group(1))

        steps.append({
            "step": step_index,
            "file": file_path,
            "sbom": sbom,
            "components": get_components_from_sbom(sbom)
        })

    return steps


# Confronta gli SBOM dei vari step del Dockerfile per individuare i componenti che compaiono per la prima volta durante la build.
# Per ogni nuovo componente salva lo step e il file SBOM in cui è stato rilevato.
def find_component_origins(step_sboms):
    origins = {}

    previous_components = set()

    for step_data in step_sboms:

        step = step_data["step"]
        components = step_data["components"]

        current_components = set(components.keys())

        new_components = (current_components - previous_components)

        for purl in new_components:

            component = components[purl]

            origins[purl] = {
                "name": component.get(
                    "name",
                    "unknown"
                ),
                "version": component.get(
                    "version",
                    "unknown"
                ),
                "purl": purl,
                "origin": "dockerfile",
                "origin_step": step,
                "origin_file": os.path.basename(
                    step_data["file"]
                ),
                "type": "introduced"
            }

        previous_components.update(current_components)

    return origins


# Carica gli SBOM generati a partire dai file di dipendenze presenti nel repository, come requirements.txt, pyproject.toml o altri file analizzati.
# Per ogni componente salva il file SBOM da cui è stato ottenuto.
def load_manifest_components(STORAGE_DIR):

    manifest_components = {}
    dependency_map = {}

    folders = [
        "manifests",
        "dependencies"
    ]

    for folder in folders:

        folder_path = os.path.join(STORAGE_DIR, folder)

        if not os.path.exists(folder_path):
            continue

        for file_path in glob.glob(os.path.join(folder_path, "*.json")):

            sbom = load_sbom_file(file_path)

            if not sbom:
                continue

            components = get_components_from_sbom(sbom)

            sbom_dependencies = get_component_dependencies(sbom)

            for purl, component in components.items():

                if purl not in manifest_components:

                    manifest_components[purl] = {
                        "name": component.get(
                            "name",
                            "unknown"
                        ),
                        "version": component.get(
                            "version",
                            "unknown"
                        ),
                        "purl": purl,
                        "origin": "manifest",
                        "origin_file": os.path.basename(
                            file_path
                        )
                    }

            dependency_map.update(sbom_dependencies)

    return manifest_components, dependency_map