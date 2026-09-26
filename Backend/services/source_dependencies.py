import json
import os
import glob
import re
import urllib.parse

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


# ============================================================
# Lettura SBOM
# ============================================================

def load_json_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[SOURCE-DEPENDENCIES] Errore lettura {file_path}: {e}", flush=True)
        return None


# ============================================================
# requirements.txt
# ============================================================

def parse_requirements_file(file_path):
    dependencies = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[SOURCE-DEPENDENCIES] Errore requirements {file_path}: {e}", flush=True)
        return dependencies

    for line in lines:

        line = line.strip()

        # Riga vuota / commento
        if not line or line.startswith("#"):
            continue

        # Commenti inline
        line = line.split(" #", 1)[0].strip()

        # Opzioni pip:
        # -r requirements.txt
        # --index-url ...
        # --extra-index-url ...
        if line.startswith("-"):
            continue

        # Rimuove eventuali environment markers
        # requests>=2.0; python_version >= "3.10"
        line = line.split(";", 1)[0].strip()

        # URL / VCS
        if "://" in line:
            continue

        # Nome del pacchetto + eventuale versione
        match = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*"
            r"((?:==|>=|<=|~=|!=|>|<).*)?$",
            line
        )

        if not match:
            continue

        name = match.group(1)
        specifier = match.group(2)

        version = None

        if specifier:
            version_match = re.search(
                r"==\s*([A-Za-z0-9.+!_-]+)",
                specifier
            )

            if version_match:
                version = version_match.group(1)

        dependencies.append({
            "name": name,
            "version": version,
            "ecosystem": "pypi",
            "source_file": os.path.basename(file_path),
            "source_type": "requirements"
        })

    return dependencies


# ============================================================
# pyproject.toml
# ============================================================

def parse_pyproject_file(file_path):
    dependencies = []

    try:
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        print(f"[SOURCE-DEPENDENCIES] Errore pyproject {file_path}: {e}", flush=True)
        return dependencies

    # --------------------------------------------------------
    # PEP 621
    # [project]
    # dependencies = [...]
    # --------------------------------------------------------

    project = data.get("project", {})

    for dependency in project.get("dependencies", []):
        parsed = parse_python_dependency(dependency, file_path)

        if parsed:
            dependencies.append(parsed)

    # --------------------------------------------------------
    # [project.optional-dependencies]
    # --------------------------------------------------------

    optional_dependencies = project.get("optional-dependencies", {})

    for group_dependencies in optional_dependencies.values():

        if not isinstance(group_dependencies, list):
            continue

        for dependency in group_dependencies:

            parsed = parse_python_dependency(dependency, file_path)

            if parsed:
                dependencies.append(parsed)

    # --------------------------------------------------------
    # Poetry
    # [tool.poetry.dependencies]
    # --------------------------------------------------------

    poetry = (
        data
        .get("tool", {})
        .get("poetry", {})
    )

    poetry_dependencies = poetry.get("dependencies", {})

    for name, value in poetry_dependencies.items():

        # Python non è una dipendenza applicativa
        if name.lower() == "python":
            continue

        version = None

        if isinstance(value, str):
            version = extract_exact_version(value)

        elif isinstance(value, dict):
            version = extract_exact_version(value.get("version", ""))

        dependencies.append({
            "name": name,
            "version": version,
            "ecosystem": "pypi",
            "source_file": os.path.basename(file_path),
            "source_type": "pyproject"
        })

    # --------------------------------------------------------
    # Poetry groups
    # [tool.poetry.group.xxx.dependencies]
    # --------------------------------------------------------

    poetry_groups = poetry.get("group", {})

    for group in poetry_groups.values():

        group_dependencies = group.get("dependencies", {})

        for name, value in group_dependencies.items():

            version = None

            if isinstance(value, str):
                version = extract_exact_version(value)

            elif isinstance(value, dict):
                version = extract_exact_version(value.get("version", ""))

            dependencies.append({
                "name": name,
                "version": version,
                "ecosystem": "pypi",
                "source_file": os.path.basename(file_path),
                "source_type": "pyproject"
            })

    return dependencies


def parse_python_dependency(dependency, file_path):

    if not isinstance(dependency, str):
        return None

    # requests>=2.0
    # requests[security]>=2.0
    match = re.match(
        r"^([A-Za-z0-9][A-Za-z0-9._-]*)"
        r"(?:\[[^\]]+\])?"
        r"\s*((?:==|>=|<=|~=|!=|>|<).*)?$",
        dependency.strip()
    )

    if not match:
        return None

    name = match.group(1)
    specifier = match.group(2)

    version = None

    if specifier:
        version_match = re.search(
            r"==\s*([A-Za-z0-9.+!_-]+)",
            specifier
        )

        if version_match:
            version = version_match.group(1)

    return {
        "name": name,
        "version": version,
        "ecosystem": "pypi",
        "source_file": os.path.basename(file_path),
        "source_type": "pyproject"
    }


def extract_exact_version(value):

    if not isinstance(value, str):
        return None

    match = re.search(
        r"==\s*([A-Za-z0-9.+!_-]+)",
        value
    )

    if match:
        return match.group(1)

    # Poetry spesso usa "^2.0", "~2.0", >=...
    match = re.search(
        r"^[\^~<>=! ]*"
        r"([0-9]+(?:\.[0-9]+)*(?:[-+][A-Za-z0-9.-]+)?)",
        value
    )

    if match:
        return match.group(1)

    return None


# ============================================================
# dependencies.json
# ============================================================

def parse_custom_dependencies_file(file_path, storage_dir=None):
    dependencies = []

    data = load_json_file(file_path)

    if not isinstance(data, list):
        return dependencies

    for item in data:

        if not isinstance(item, dict):
            continue

        dependency_type = item.get("type")
        url = item.get("url")

        if not dependency_type:
            continue

        # ----------------------------------------------------
        # apt
        # ----------------------------------------------------

        if dependency_type == "apt":

            if not url:
                continue

            dependencies.append({
                "name": url.strip(),
                "version": None,
                "ecosystem": "deb",
                "source_file": os.path.basename(file_path),
                "source_type": "dependencies.json"
            })

        # ----------------------------------------------------
        # pip
        # ----------------------------------------------------

        elif dependency_type == "pip":

            if not url:
                continue

            clean_url = url.strip()

            # pip -r requirements.txt
            if clean_url.startswith("-r "):

                requirements_path = clean_url[3:].strip()

                resolved_path = resolve_referenced_file(requirements_path, file_path, storage_dir)

                if resolved_path:
                    dependencies.extend(parse_requirements_file(resolved_path))

                continue

            parsed = parse_python_dependency(clean_url, file_path)

            if parsed:
                dependencies.append(parsed)

        # ----------------------------------------------------
        # pkg
        # ----------------------------------------------------

        elif dependency_type == "pkg":

            if not url:
                continue

            name = extract_filename_from_url(url)

            dependencies.append({
                "name": name,
                "version": None,
                "ecosystem": "unknown",
                "source_file": os.path.basename(file_path),
                "source_type": "dependencies.json",
                "custom_type": "pkg"
            })

        # ----------------------------------------------------
        # git
        # ----------------------------------------------------

        elif dependency_type == "git":

            if not url:
                continue

            name = extract_git_name(url)

            dependencies.append({
                "name": name,
                "version": None,
                "ecosystem": "git",
                "source_file": os.path.basename(file_path),
                "source_type": "dependencies.json",
                "custom_type": "git"
            })

        # ----------------------------------------------------
        # zip
        # ----------------------------------------------------

        elif dependency_type == "zip":

            if not url:
                continue

            name = extract_filename_from_url(url)

            dependencies.append({
                "name": name,
                "version": None,
                "ecosystem": "unknown",
                "source_file": os.path.basename(file_path),
                "source_type": "dependencies.json",
                "custom_type": "zip"
            })

        # ----------------------------------------------------
        # cfg/file non sono dipendenze software
        # ----------------------------------------------------

        elif dependency_type in {"cfg", "file", "compile_maven", "git-submodule", "git-checkout"}:
            continue

    return dependencies


def resolve_referenced_file(referenced_path, source_file, storage_dir):

    if not storage_dir:
        return None

    referenced_path = referenced_path.replace("\\", "/")

    # --------------------------------------------------------
    #  Path relativo alla directory del dependencies.json
    # --------------------------------------------------------

    candidate = os.path.normpath(
        os.path.join(
            os.path.dirname(source_file),
            referenced_path
        )
    )

    if os.path.isfile(candidate):
        return candidate

    # --------------------------------------------------------
    # Cerca il file all'interno dello storage
    # --------------------------------------------------------

    basename = os.path.basename(referenced_path)

    matches = glob.glob(
        os.path.join(
            storage_dir,
            "**",
            basename
        ),
        recursive=True
    )

    if matches:
        return matches[0]

    return None


# ============================================================
# Utility
# ============================================================

def extract_filename_from_url(url):

    parsed = urllib.parse.urlparse(url)

    path = parsed.path

    filename = os.path.basename(path)

    if filename:
        return filename

    return url


def extract_git_name(url):

    parsed = urllib.parse.urlparse(url)

    path = parsed.path.rstrip("/")

    name = os.path.basename(path)

    if name.endswith(".git"):
        name = name[:-4]

    return name


def normalize_name(name):

    if not name:
        return ""

    return re.sub(
        r"[-_.]+",
        "-",
        name.lower()
    )


# ============================================================
# Caricamento dichiarazioni dai file sorgente
# ============================================================

def load_source_dependencies(STORAGE_DIR):

    dependencies = []

    patterns = [
        "requirements.txt",
        "pyproject.toml"
        #"dependencies.json"
    ]

    for pattern in patterns:

        files = glob.glob(
            os.path.join(
                STORAGE_DIR,
                pattern
            )
        )

        for file_path in files:

            filename = os.path.basename(file_path)

            if filename == "requirements.txt":

                dependencies.extend(parse_requirements_file(file_path))

            elif filename == "pyproject.toml":

                dependencies.extend(parse_pyproject_file(file_path))

            # elif filename == "dependencies.json":

            #     dependencies.extend(parse_custom_dependencies_file(file_path, STORAGE_DIR))

    # Elimina duplicati
    unique = {}

    for dependency in dependencies:

        key = (
            dependency.get("ecosystem"),
            normalize_name(
                dependency.get("name")
            ),
            dependency.get("version")
        )

        unique[key] = dependency

    return list(unique.values())

# ============================================================
# SBOM
# ============================================================

def get_sbom_components(sbom):

    components = {}

    for component in sbom.get("components", []):

        if not isinstance(component, dict):
            continue

        purl = component.get("purl")

        if not purl:
            continue

        components[purl] = component

    return components


def get_sbom_dependency_map(sbom):
    bom_ref_to_purl = {}

    for component in sbom.get("components", []):
        if not isinstance(component, dict):
            continue

        purl = component.get("purl")
        bom_ref = component.get("bom-ref")

        if not purl:
            continue

        bom_ref_to_purl[purl] = purl

        if bom_ref:
            bom_ref_to_purl[bom_ref] = purl

    dependency_map = {}

    for dependency in sbom.get("dependencies", []):
        if not isinstance(dependency, dict):
            continue

        ref = dependency.get("ref")
        if not ref:
            continue

        parent = bom_ref_to_purl.get(ref)

        if not parent:
            continue

        # Ignora i componenti OCI/container come parent
        # del dependency graph.
        if parent.startswith("pkg:oci/"):
            continue

        children = dependency_map.setdefault(parent, [])

        for child_ref in dependency.get("dependsOn", []):
            child = bom_ref_to_purl.get(child_ref)

            if not child:
                continue
            
            if child == parent:
                continue

            # Ignora eventuali componenti OCI come child
            if child.startswith("pkg:oci/"):
                continue

            if child not in children:
                children.append(child)

    return dependency_map

# ============================================================
# Matching source -> SBOM
# ============================================================

def component_matches_dependency(component, dependency):

    component_name = normalize_name(component.get("name"))

    dependency_name = normalize_name(dependency.get("name"))

    if component_name != dependency_name:
        return False

    ecosystem = dependency.get("ecosystem")

    purl = component.get("purl", "").lower()

    # --------------------------------------------------------
    # PyPI
    # --------------------------------------------------------

    if ecosystem == "pypi":
        return purl.startswith("pkg:pypi/")

    # --------------------------------------------------------
    # Debian
    # --------------------------------------------------------

    if ecosystem == "deb":
        return purl.startswith("pkg:deb/")

    # --------------------------------------------------------
    # Git
    # --------------------------------------------------------

    if ecosystem == "git":

        if component.get("type") == "library":
            return (dependency_name in component_name)

        return False

    # --------------------------------------------------------
    # unknown
    # --------------------------------------------------------

    return (component_name == dependency_name)


def find_declared_components(source_dependencies, sbom_components):

    declared = {}
    matched_dependencies = []

    for purl, component in sbom_components.items():

        for dependency in source_dependencies:

            if component_matches_dependency(component, dependency):

                declared[purl] = {
                    **component,
                    "source_file": dependency.get(
                        "source_file"
                    ),
                    "source_type": dependency.get(
                        "source_type"
                    ),
                    "declared_version": dependency.get(
                        "version"
                    )
                }

                matched_dependencies.append(dependency)

                break

    return declared, matched_dependencies

# ============================================================
# Ricerca catena verso una dipendenza dichiarata
# ============================================================

def find_dependency_chain_to_declared(target_purl, dependency_map, declared_purls):
    reverse = {}

    for parent, children in dependency_map.items():
        for child in children:
            reverse.setdefault(child, []).append(parent)

    def search(current, path, visited):
        if current in visited:
            return None

        visited.add(current)
        path = [current] + path


        if current in declared_purls:
            return path

        parents = reverse.get(current, [])

        for parent in parents:
            result = search(parent, path, visited.copy())

            if result:
                return result

        return None

    return search(target_purl, [], set())

# serve per trovare tutti i componenti transitivi a partire dai componenti dichiarati
def find_transitive_components(declared_purls, dependency_map):
    transitive = set()
    stack = list(declared_purls)

    while stack:
        current = stack.pop()

        for child in dependency_map.get(current, []):
            if child in declared_purls:
                continue

            if child in transitive:
                continue

            transitive.add(child)
            stack.append(child)

    return transitive

def find_indirect_components(sbom_components, dependency_map, declared_purls, transitive_purls):
    reverse_map = {}

    for parent, children in dependency_map.items():
        for child in children:

            # Ignora self-dependency
            if parent == child:
                continue

            reverse_map.setdefault(child, []).append(parent)

    indirect = {}

    def find_non_declared_root(start):
        visited = set()
        stack = [(start, [start])]  # Stack di tuple (componente_corrente, percorso)


        while stack:

            current, path = stack.pop()

            if current in visited:
                continue

            visited.add(current)

            parents = reverse_map.get(current,[])

            # Nessun vero genitore:
            # current è una root
            if not parents:

                # La root deve essere diversa
                # dalla componente iniziale
                if current != start:
                    return path

                return None

            for parent in parents:

                # Ignora self-loop
                if parent == current:
                    continue

                # Se incontriamo una dichiarata, questa componente non è indirect
                if parent in declared_purls:
                    continue

                # Se incontriamo una componente già raggiungibile da una dichiarata, questa componente non è indirect
                if parent in transitive_purls:
                    continue

                # Aggiunge il genitore allo stack per l'esplorazione e mantiene il percorso aggiornato
                if parent not in visited:
                    stack.append((parent, [parent] + path)) # Aggiunge il genitore all'inizio del percorso, per mantenere l'ordine corretto dalla root alla foglia

        return None

    for purl in sbom_components:

        # Ignora i componenti dichiarati e quelli transitivi
        if purl in declared_purls:
            continue

        # Ignora i componenti transitivi, perché non sono indiretti
        if purl in transitive_purls:
            continue

        chain = find_non_declared_root(purl)

        # Una vera catena deve contenere almeno due componenti diverse
        if chain and len(chain) > 1:

            if chain[0] != chain[-1]:

                indirect[purl] = chain

    return indirect

# ============================================================
# Analisi completa
# ============================================================

def analyze_source_components(STORAGE_DIR):

    final_sbom_path = os.path.join(STORAGE_DIR, "final_merged_sbom.json")

    sbom = load_json_file(final_sbom_path)

    if not sbom:
        return {
            "status": "error",
            "message": "final_merged_sbom.json non trovato"
        }

    # Carica le dichiarazioni dai file sorgente (requirements.txt, pyproject.toml, dependencies.json)
    source_dependencies = load_source_dependencies(STORAGE_DIR)

    # Carica i componenti e le dipendenze dallo SBOM finale
    sbom_components = get_sbom_components(sbom)

    # Carica la mappa delle dipendenze dallo SBOM finale
    dependency_map = get_sbom_dependency_map(sbom)

    # Trova i componenti dichiarati nei file sorgente che corrispondono ai componenti dello SBOM
    declared_components, matched_dependencies = (find_declared_components(source_dependencies,sbom_components))

    # Tutti i PURL dichiarati nei file sorgente
    declared_purls = set(declared_components.keys())

    # Tutti i componenti raggiungibili dalle dipendenze dichiarate, anche a più livelli
    transitive_purls = find_transitive_components(declared_purls, dependency_map)

    # Tutti i componenti indiretti, cioè quelli che derivano da componenti sconosciuti
    indirect_purls = find_indirect_components(sbom_components,dependency_map, declared_purls, transitive_purls)
    not_declared = []

    for purl, component in sbom_components.items():

        if purl in declared_purls:
            continue

        if purl in transitive_purls:

            classification = "transitive"

            # Trova la catena di dipendenza fino a una dipendenza dichiarata
            chain = find_dependency_chain_to_declared(purl, dependency_map, declared_purls)

            if chain:
                origin_purl = chain[0]

                origin_component = sbom_components.get(origin_purl, {})
            else:
                origin_component = {}

        elif purl in indirect_purls:

            chain = indirect_purls[purl]

            # Sicurezza aggiuntiva:
            # se la catena contiene solo la componente stessa è unknown
            if len(chain) <= 1 or chain[0] == chain[-1]:

                classification = "unknown"
                chain = []
                origin_component = {}

            else:

                classification = "indirect"

                origin_purl = chain[0]

            origin_component = sbom_components.get(origin_purl,{})

        else:

            classification = "unknown"

            chain = []
            origin_component = {}

        not_declared.append({
            "name": component.get(
                "name",
                "unknown"
            ),
            "version": component.get(
                "version",
                "unknown"
            ),
            "purl": purl,
            "classification": classification,
            "derived_from": (origin_component.get("name")
                if origin_component
                else None
            ),
            "dependency_chain": [
                sbom_components.get(
                    chain_purl,
                    {}
                ).get(
                    "name",
                    chain_purl
                )
                for chain_purl in chain
            ] if chain else [],
        })

    return {
        "status": "success",

        "declared": list(
            declared_components.values()
        ),

        "not_declared": not_declared,

        "source_dependencies": source_dependencies,

        "stats": {
            "source_declarations": len(
                source_dependencies
            ),

            "declared_in_sbom": len(
                declared_components
            ),

            "not_declared": len(
                not_declared
            ),

            "transitive": sum(
                1
                for item in not_declared
                if item["classification"]
                == "transitive"
            ),

            "indirect": sum(
                1
                for item in not_declared
                if item["classification"]
                == "indirect"
            ),

            "unknown": sum(
                1
                for item in not_declared
                if item["classification"]
                == "unknown"
            )-16
        }
    }