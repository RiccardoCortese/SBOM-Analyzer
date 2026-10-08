import json
import os
from config import STORAGE_DIR

def load_components(sbom_path: str) -> dict:
    """
    Carica i componenti da uno SBOM CycloneDX.

    Ritorna:
    {
        "purl_componente": {
            "name": "...",
            "version": "...",
            "type": "...",
            "purl": "..."
        }
    }
    """

    with open(sbom_path, "r", encoding="utf-8") as f:
        sbom = json.load(f)

    components = {}

    for component in sbom.get("components", []):

        purl = component.get("purl")

        if not purl:
            continue

        components[purl] = {
            "name": component.get("name"),
            "version": component.get("version"),
            "type": component.get("type"),
            "purl": purl
        }

    return components


def update_removed_components(removed, added, output_path):
    """
    Aggiorna il file esistente:
    - aggiunge le nuove librerie rimosse;
    - elimina quelle reintrodotte;
    - non riscrive il file se non ci sono modifiche.
    """
    output_path = os.path.join(STORAGE_DIR, output_path)
    # Legge il file esistente
    if os.path.exists(output_path):
        with open(output_path, "r", encoding="utf-8") as f:
            existing = json.load(f)
    else:
        existing = []

    # Indicizza le librerie già registrate
    existing_by_purl = {
        comp["purl"]: comp
        for comp in existing
        if isinstance(comp, dict) and comp.get("purl")
    }

    modified = False

    # Elimina le librerie reintrodotte
    for comp in added:
        purl = comp.get("purl")

        if purl and purl in existing_by_purl:
            del existing_by_purl[purl]
            modified = True
            print(f"[REMOVED] Libreria reintrodotta: {purl}")

    # Aggiunge le nuove librerie rimosse
    for comp in removed:
        purl = comp.get("purl")

        if purl and purl not in existing_by_purl:
            existing_by_purl[purl] = comp
            modified = True
            print(f"[REMOVED] Nuova libreria rimossa: {purl}")

    # Scrive soltanto se il contenuto è cambiato
    if modified:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(
                list(existing_by_purl.values()),
                f,
                indent=4,
                ensure_ascii=False
            )

def compare_sbom(old_sbom_path: str, new_sbom_path: str, output_path: str = "removed_components.json") -> dict:
    """
    Confronta due SBOM CycloneDX consecutivi.

    old -> step precedente
    new -> step corrente

    Identifica:
    - added: componenti aggiunti
    - removed: componenti rimossi
    - changed: componenti con versione modificata

    Aggiorna inoltre il file cumulativo removed_components.json.
    """

    old_components = load_components(old_sbom_path)
    new_components = load_components(new_sbom_path)

    added = []
    removed = []
    changed = []

    print(
        f"[SBOM DIFF] Confronto:\n"
        f"  Precedente: {old_sbom_path}\n"
        f"  Corrente:   {new_sbom_path}\n"
        f"  Componenti precedenti: {len(old_components)}\n"
        f"  Componenti correnti:   {len(new_components)}",
        flush=True
    )

    # Individua i componenti aggiunti e quelli modificati
    for purl, info in new_components.items():

        if purl not in old_components:

            added.append({
                "name": purl,
                **info
            })

        else:

            old_version = old_components[purl].get("version")
            new_version = info.get("version")

            if old_version != new_version:

                changed.append({
                    "name": purl,
                    "old_version": old_version,
                    "new_version": new_version,
                    "purl": purl
                })

    # Individua i componenti rimossi
    for purl, info in old_components.items():

        if purl not in new_components:

            removed.append({
                "name": purl,
                **info
            })

    # Aggiorna sempre il file cumulativo:
    # anche le aggiunte possono eliminare rimozioni precedenti.
    update_removed_components(removed=removed, added=added, output_path=output_path)

    print(
        f"[SBOM DIFF] Risultato confronto:\n"
        f"  Aggiunti:  {len(added)}\n"
        f"  Rimossi:   {len(removed)}\n"
        f"  Modificati: {len(changed)}",
        flush=True
    )

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed)
        }
    }


def reset_removed_components(output_path: str = "removed_components.json"):
    """
    Inizializza il file delle rimozioni per una nuova scansione.

    Chiamare una sola volta all'inizio dell'analisi Docker,
    non prima di ogni confronto tra SBOM.
    """
    output_path = os.path.join(STORAGE_DIR, output_path)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump([], f, indent=4, ensure_ascii=False)

    print(
        f"[REMOVED COMPONENTS] File inizializzato: {output_path}",
        flush=True
    )