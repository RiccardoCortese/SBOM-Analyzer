
import json
import os
import glob
import re
from collections import defaultdict, deque


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

    # Include anche il componente radice, se presente
    root = sbom.get("metadata", {}).get("component", {})

    if isinstance(root, dict):
        root_purl = root.get("purl")
        root_ref = root.get("bom-ref")

        if root_purl and root_ref:
            mapping[root_ref] = root_purl

        if root_purl:
            mapping[root_purl] = root_purl

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

        # Unisce eventuali relazioni duplicate senza sovrascriverle
        dependencies.setdefault(parent_purl, [])
        dependencies[parent_purl] = list(
            dict.fromkeys(
                dependencies[parent_purl] + child_purls
            )
        )

    return dependencies


# Estrae le dipendenze direttamente dichiarate nel manifest.
# Utilizza il componente radice dello SBOM e le sue relazioni dirette.
def get_direct_manifest_purls(sbom):
    direct_purls = set()

    metadata = sbom.get("metadata", {})
    root = metadata.get("component", {})

    if not isinstance(root, dict):
        return direct_purls

    root_ref = root.get("bom-ref")
    root_purl = root.get("purl")

    if not root_ref and not root_purl:
        return direct_purls

    bom_ref_to_purl = get_bom_ref_to_purl(sbom)

    # Cerca le dipendenze direttamente collegate alla radice
    for dependency in sbom.get("dependencies", []):
        if not isinstance(dependency, dict):
            continue

        ref = dependency.get("ref")

        # La relazione deve partire dal componente radice
        if ref != root_ref and ref != root_purl:
            continue

        for child_ref in dependency.get("dependsOn", []):
            child_purl = bom_ref_to_purl.get(child_ref)

            if child_purl:
                direct_purls.add(child_purl)

    return direct_purls


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

        new_components = current_components - previous_components

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
    direct_purls = set()

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

            # Recupera le dipendenze direttamente dichiarate nel manifest
            direct_purls.update(
                get_direct_manifest_purls(sbom)
            )
            

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

            # Unisce le relazioni di dipendenza provenienti dai vari SBOM
            for parent_purl, child_purls in sbom_dependencies.items():

                dependency_map.setdefault(parent_purl, [])

                dependency_map[parent_purl] = list(
                    dict.fromkeys(
                        dependency_map[parent_purl] + child_purls
                    )
                )

    return manifest_components, dependency_map, direct_purls


# Classifica i componenti dello SBOM in base alla loro origine.
# Le dipendenze vengono classificate risalendo alle radici del grafo.
# Le dipendenze dichiarate direttamente sono "declared".
# Le dipendenze che derivano da una dipendenza diretta sono "transitive".
# Le dipendenze di cui non è possibile ricostruire la provenienza sono "unknown".
# Le dipendenze che derivano da una radice sconosciuta sono "transitive_unknown".
def classify_components(all_components, direct_purls, dependency_map):

    all_purls = set(all_components.keys())

    # Considera come dirette solo le dipendenze presenti nello SBOM finale
    direct_purls = set(direct_purls) & all_purls

    # Costruisce il grafo limitandolo ai componenti presenti nello SBOM finale
    graph = {}

    for purl in all_purls:

        graph[purl] = [
            child_purl
            for child_purl in dependency_map.get(purl, [])
            if child_purl in all_purls
        ]

    # ============================================================
    # CLASSIFICAZIONE DIPENDENZE DIRETTE
    # ============================================================

    classifications = {}

    for purl in direct_purls:
        classifications[purl] = "declared"

    # ============================================================
    # RICERCA DIPENDENZE TRANSITIVE
    # ============================================================

    # Partendo dalle dipendenze dirette, visita ricorsivamente
    # tutti i componenti raggiungibili nel grafo.
    # Questi componenti vengono classificati come transitivi.

    queue = deque(direct_purls)

    visited = set(direct_purls)

    while queue:

        current_purl = queue.popleft()

        for child_purl in graph.get(current_purl, []):

            if child_purl in visited:
                continue

            visited.add(child_purl)

            classifications[child_purl] = "transitive"

            queue.append(child_purl)

    # ============================================================
    # COMPONENTI NON RAGGIUNGIBILI DALLE DIPENDENZE DIRETTE
    # ============================================================

    # I componenti non raggiungibili dalle dipendenze dirette
    # possono essere sconosciuti oppure transitivi di sconosciute.

    remaining = all_purls - visited

    # ============================================================
    # CALCOLA LE DIPENDENZE IN INGRESSO
    # ============================================================

    # Per individuare le radici sconosciute, calcola i predecessori
    # di ogni componente rimasto nel grafo.

    incoming = defaultdict(set)

    for parent_purl in remaining:

        for child_purl in graph.get(parent_purl, []):

            if child_purl not in remaining:
                continue

            incoming[child_purl].add(parent_purl)

    # ============================================================
    # INDIVIDUA LE RADICI SCONOSCIUTE
    # ============================================================

    # I componenti non raggiungibili dalle dipendenze dirette
    # e senza predecessori nel grafo residuo vengono considerati
    # radici sconosciute.

    unknown_roots = {
        purl
        for purl in remaining
        if not incoming[purl]
    }

    for purl in unknown_roots:
        classifications[purl] = "unknown"

    # ============================================================
    # CLASSIFICA LE TRANSITIVE DI SCONOSCIUTE
    # ============================================================

    # Partendo dalle radici sconosciute, visita ricorsivamente
    # tutti i componenti discendenti.
    # Questi componenti vengono classificati come transitive_unknown.

    queue = deque(unknown_roots)

    unknown_visited = set(unknown_roots)

    while queue:

        current_purl = queue.popleft()

        for child_purl in graph.get(current_purl, []):

            if child_purl not in remaining:
                continue

            if child_purl in unknown_visited:
                continue

            unknown_visited.add(child_purl)

            classifications[child_purl] = "transitive_unknown"

            queue.append(child_purl)

    # ============================================================
    # GESTIONE COMPONENTI RESIDUI
    # ============================================================

    # Gli eventuali componenti rimasti non raggiungibili da alcuna
    # radice identificabile, ad esempio cicli isolati, vengono
    # classificati come sconosciuti.

    unresolved = remaining - unknown_visited

    for purl in unresolved:
        classifications[purl] = "unknown"

    # ============================================================
    # COSTRUISCE IL RISULTATO
    # ============================================================

    result = {}

    for purl, component in all_components.items():

        result[purl] = {
            **component,
            "classification": classifications.get(
                purl,
                "unknown"
            )
        }

    return result


# Classifica i componenti dello SBOM finale utilizzando i manifest
# e le relazioni di dipendenza raccolte.
def classify_final_sbom(STORAGE_DIR, final_sbom_path):

    # Carica i componenti e le dipendenze dei manifest
    manifest_components, manifest_dependencies, direct_purls = (
        load_manifest_components(STORAGE_DIR)
    )

    # Carica lo SBOM finale
    final_sbom = load_sbom_file(final_sbom_path)

    if not final_sbom:
        print(
            f"[PROVENANCE] SBOM finale non valido: {final_sbom_path}",
            flush=True
        )
        return None

    all_components = get_components_from_sbom(final_sbom)

    # Recupera le relazioni di dipendenza dello SBOM finale
    final_dependencies = get_component_dependencies(final_sbom)

    # Unisce le relazioni provenienti dai manifest e dallo SBOM finale
    dependency_map = {}

    for source_map in [
        manifest_dependencies,
        final_dependencies
    ]:

        for parent_purl, child_purls in source_map.items():

            dependency_map.setdefault(parent_purl, [])

            dependency_map[parent_purl] = list(
                dict.fromkeys(
                    dependency_map[parent_purl] + child_purls
                )
            )

    # Classifica tutti i componenti dello SBOM finale
    classified_components = classify_components(
        all_components,
        direct_purls,
        dependency_map
    )

    # ============================================================
    # SALVA RISULTATO
    # ============================================================

    output = {
        "components": list(
            classified_components.values()
        ),
        "count": len(classified_components)
    }

    output_file = os.path.join(
        STORAGE_DIR,
        "classified_components.json"
    )

    try:
        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                output,
                f,
                indent=4,
                ensure_ascii=False
            )

        print(
            f"[PROVENANCE] Componenti classificati: "
            f"{len(classified_components)}",
            flush=True
        )

        print(
            f"[PROVENANCE] File salvato: {output_file}",
            flush=True
        )

        # Stampa il riepilogo delle classificazioni
        classification_counts = defaultdict(int)

        for component in classified_components.values():

            classification_counts[
                component["classification"]
            ] += 1

        for classification in [
            "declared",
            "transitive",
            "unknown",
            "transitive_unknown"
        ]:

            print(
                f"[PROVENANCE] {classification}: "
                f"{classification_counts[classification]}",
                flush=True
            )

        return output

    except Exception as e:

        print(
            f"[PROVENANCE] Errore salvataggio "
            f"classified_components.json: {e}",
            flush=True
        )

        return None


# Salva i componenti non dichiarati in un file JSON.
def save_not_declared_components(STORAGE_DIR, not_declared_components):

    output = {
        "components": not_declared_components,
        "count": len(not_declared_components)
    }

    output_file = os.path.join(
        STORAGE_DIR,
        "not_declared_components.json"
    )

    try:
        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as f:
            json.dump(
                output,
                f,
                indent=4,
                ensure_ascii=False
            )

        print(
            f"[PROVENANCE] Componenti non dichiarati: "
            f"{len(not_declared_components)}",
            flush=True
        )

        print(
            f"[PROVENANCE] File salvato: {output_file}",
            flush=True
        )

        return output

    except Exception as e:

        print(
            f"[PROVENANCE] Errore salvataggio "
            f"not_declared_components.json: {e}",
            flush=True
        )

        return None

# Salva i componenti non dichiarati che presentano almeno una vulnerabilità in un file JSON.

def save_non_declared_vulnerable_components(STORAGE_DIR):

    not_declared_file = os.path.join(
        STORAGE_DIR,
        "not_declared_components.json"
    )

    trivy_file = os.path.join(
        STORAGE_DIR,
        "trivy_vulnerabilities.json"
    )

    grouped_file = os.path.join(
        STORAGE_DIR,
        "grouped_vulnerabilities.json"
    )

    # ============================================================
    # CARICA COMPONENTI NON DICHIARATI
    # ============================================================

    if not os.path.exists(not_declared_file):
        print(
            f"[PROVENANCE] File non trovato: {not_declared_file}",
            flush=True
        )
        return None

    try:
        with open(not_declared_file, "r", encoding="utf-8") as f:
            not_declared_data = json.load(f)

        # Supporta sia il nuovo formato {count, components}
        # sia il vecchio formato con lista diretta.
        if isinstance(not_declared_data, dict):
            not_declared_components = not_declared_data.get(
                "components", []
            )
        elif isinstance(not_declared_data, list):
            not_declared_components = not_declared_data
        else:
            raise ValueError(
                "Formato non valido in not_declared_components.json"
            )

        if not isinstance(not_declared_components, list):
            raise ValueError(
                "'components' deve essere una lista"
            )

        # Mantiene solo i componenti validi
        not_declared_components = [
            component
            for component in not_declared_components
            if isinstance(component, dict)
        ]

    except Exception as e:
        print(
            f"[PROVENANCE] Errore lettura "
            f"not_declared_components.json: {e}",
            flush=True
        )
        return None

    # PURL dei componenti non dichiarati
    not_declared_purls = {
        component.get("purl")
        for component in not_declared_components
        if component.get("purl")
    }

    # PURL -> dati completi del componente
    not_declared_by_purl = {
        component.get("purl"): component
        for component in not_declared_components
        if component.get("purl")
    }

    # ============================================================
    # CARICA TRIVY
    # ============================================================

    if not os.path.exists(trivy_file):
        print(
            f"[PROVENANCE] File Trivy non trovato: {trivy_file}",
            flush=True
        )
        return None

    try:
        with open(trivy_file, "r", encoding="utf-8") as f:
            trivy_data = json.load(f)

    except Exception as e:
        print(
            f"[PROVENANCE] Errore lettura "
            f"trivy_vulnerabilities.json: {e}",
            flush=True
        )
        return None

    # ============================================================
    # CARICA NUMERO COMPONENTI VULNERABILI TOTALI
    # ============================================================

    if not os.path.exists(grouped_file):
        print(
            f"[PROVENANCE] File non trovato: {grouped_file}",
            flush=True
        )
        return None

    try:
        with open(grouped_file, "r", encoding="utf-8") as f:
            grouped_data = json.load(f)

        # Nuovo formato: {"count": N, "components": [...]}
        if isinstance(grouped_data, dict):
            total_vulnerable_components = grouped_data.get(
                "count",
                len(grouped_data.get("components", []))
            )

        # Compatibilità con il vecchio formato: lista diretta
        elif isinstance(grouped_data, list):
            total_vulnerable_components = len(grouped_data)

        else:
            raise ValueError(
                "Formato non valido in grouped_vulnerabilities.json"
            )

        if not isinstance(total_vulnerable_components, int):
            raise ValueError(
                "Il campo 'count' deve essere un intero"
            )

    except Exception as e:
        print(
            f"[PROVENANCE] Errore lettura "
            f"grouped_vulnerabilities.json: {e}",
            flush=True
        )
        return None

    # ============================================================
    # COMPONENTI VULNERABILI
    # ============================================================

    # PURL -> dati del componente e lista CVE
    vulnerable_components = {}

    for result in trivy_data.get("Results", []):

        vulnerabilities = (
            result.get("Vulnerabilities", [])
            or []
        )

        for vulnerability in vulnerabilities:

            purl = (
                vulnerability
                .get("PkgIdentifier", {})
                .get("PURL")
            )

            if not purl:
                continue

            cve_id = vulnerability.get("VulnerabilityID")

            # ====================================================
            # SOLO COMPONENTI NON DICHIARATI
            # ====================================================

            if purl not in not_declared_purls:
                continue

            component = not_declared_by_purl[purl]

            if purl not in vulnerable_components:

                vulnerable_components[purl] = {
                    "name": component.get(
                        "name",
                        "unknown"
                    ),
                    "version": component.get(
                        "version",
                        "unknown"
                    ),
                    "purl": purl,
                    "classification": component.get(
                        "classification",
                        "unknown"
                    ),
                    "derived_from": component.get(
                        "derived_from"
                    ),
                    "dependency_chain": component.get(
                        "dependency_chain",
                        []
                    ),
                    "cves": []
                }

            if cve_id:
                vulnerable_components[purl]["cves"].append(
                    cve_id
                )

    # ============================================================
    # RIMUOVE CVE DUPLICATE
    # ============================================================

    for component in vulnerable_components.values():

        component["cves"] = list(
            dict.fromkeys(component["cves"])
        )

    # ============================================================
    # COMPONENTI VULNERABILI UNKNOWN
    # ============================================================

    unknown_vulnerable_components = [
        component
        for component in vulnerable_components.values()
        if component.get("classification") == "unknown"
    ]

    # ============================================================
    # COMPONENTI VULNERABILI TRANSITIVE UNKNOWN
    # ============================================================

    transitive_unknown_vulnerable_components = [
        component
        for component in vulnerable_components.values()
        if component.get("classification") == "transitive_unknown"
    ]

    # ============================================================
    # CALCOLA METRICHE
    # ============================================================

    total_non_declared_vulnerable = len(
        vulnerable_components
    )

    total_unknown_vulnerable = len(
        unknown_vulnerable_components
    )

    total_transitive_unknown_vulnerable = len(
        transitive_unknown_vulnerable_components
    )

    total_unknown_or_transitive_unknown = (
        total_unknown_vulnerable
        + total_transitive_unknown_vulnerable
    )

    percentage = 0

    if total_vulnerable_components > 0:

        percentage = (
            total_unknown_or_transitive_unknown
            / total_vulnerable_components
        ) * 100

    # ============================================================
    # OUTPUT
    # ============================================================

    output = {
        "components": list(
            vulnerable_components.values()
        ),
        "count": total_non_declared_vulnerable,

        "unknown_vulnerable_components": (
            unknown_vulnerable_components
        ),
        "unknown_vulnerable_count": (
            total_unknown_vulnerable
        ),

        "transitive_unknown_vulnerable_components": (
            transitive_unknown_vulnerable_components
        ),
        "transitive_unknown_vulnerable_count": (
            total_transitive_unknown_vulnerable
        ),

        "unknown_or_transitive_unknown_count": (
            total_unknown_or_transitive_unknown
        ),

        "total_vulnerable_components": (
            total_vulnerable_components
        ),

        "percentage_unknown_or_transitive_unknown": (
            percentage
        )
    }

    output_file = os.path.join(
        STORAGE_DIR,
        "non_declared_vulnerable_components.json"
    )

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(
                output,
                f,
                indent=4,
                ensure_ascii=False
            )

    except Exception as e:
        print(
            f"[PROVENANCE] Errore salvataggio "
            f"non_declared_vulnerable_components.json: {e}",
            flush=True
        )
        return None

    # ============================================================
    # LOG
    # ============================================================

    print(
        f"[PROVENANCE] Componenti vulnerabili totali "
        f"(grouped): {total_vulnerable_components}",
        flush=True
    )

    print(
        f"[PROVENANCE] Componenti non dichiarati vulnerabili: "
        f"{total_non_declared_vulnerable}",
        flush=True
    )

    print(
        f"[PROVENANCE] Vulnerabili sconosciuti: "
        f"{total_unknown_vulnerable}",
        flush=True
    )

    print(
        f"[PROVENANCE] Vulnerabili transitivi sconosciuti: "
        f"{total_transitive_unknown_vulnerable}",
        flush=True
    )

    print(
        f"[PROVENANCE] Vulnerabili sconosciuti o transitivi sconosciuti: "
        f"{total_unknown_or_transitive_unknown}",
        flush=True
    )

    print(
        f"[PROVENANCE] Percentuale sconosciuti/transitivi sconosciuti: "
        f"{percentage:.2f}%",
        flush=True
    )

    return output