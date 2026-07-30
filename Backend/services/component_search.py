import os
import json

from services.sbom_parser import build_universal_hierarchy

def search_component(component, sbom_dir):

    results = []

    search_folders = [
        "manifests",
        "dependencies",
        "docker_sbom_steps"
    ]


    sbom_files = []


    # Cerca nelle cartelle specifiche
    for folder in search_folders:

        folder_path = os.path.join(sbom_dir, folder)

        if not os.path.exists(folder_path):
            continue

        for root, _, files in os.walk(folder_path):

            for file in files:

                if file.endswith(".json"):
                    sbom_files.append(
                        os.path.join(root, file)
                    )


    # Aggiunge solo docker_sbom.json nella root
    root_sbom = os.path.join(
        sbom_dir,
        "docker_sbom.json"
    )

    if os.path.exists(root_sbom):
        sbom_files.append(root_sbom)



    # Analisi SBOM trovati
    for path in sbom_files:

        try:
            with open(path, encoding="utf-8") as f:
                sbom = json.load(f)

        except Exception:
            continue

        # Componenti già visti in questo SBOM
        seen = set()
        
        # Controllo che sia un CycloneDX valido
        if not isinstance(sbom, dict):
            continue


        for comp in sbom.get("components", []):

            if not isinstance(comp, dict):
                continue


            name = comp.get("name", "")
            purl = comp.get("purl", "")

            # Salta i duplicati
            key = (name, purl)
            if key in seen:
                continue
            seen.add(key)

            if (
                component.lower() in name.lower()
                or component.lower() in purl.lower()
            ):


                    results.append(
                        {
                            "sbom": path,
                            "name": name,
                            "purl": purl,
                            "version": comp.get("version")
                        }
                    )

    return results

def build_component_graph(component, sbom_file):

    # Lettura dello SBOM specifico
    with open(sbom_file, "r", encoding="utf-8") as f:
        sbom = json.load(f)


    # Mappa delle dipendenze CycloneDX:
    # ref -> [dipendenze]
    hierarchy = {}

    for dep in sbom.get("dependencies", []):

        ref = dep.get("ref")

        if not ref:
            continue

        hierarchy[ref] = dep.get("dependsOn", [])


    nodes = set()
    edges = []


    def visit(node):

        if node in nodes:
            return

        nodes.add(node)


        for child in hierarchy.get(node, []):

            edges.append(
                {
                    "source": node,
                    "target": child
                }
            )

            visit(child)


    # parte dal componente cercato
    visit(component)


    return {
        "nodes": [
            {
                "id": n,
                "label": n.split("/")[-1].split("@")[0]
            }
            for n in nodes
        ],
        "edges": edges
    }