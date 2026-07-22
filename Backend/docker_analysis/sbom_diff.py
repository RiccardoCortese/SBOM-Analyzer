import json


def load_components(sbom_path: str) -> dict:
    """
    Carica i componenti da uno SBOM CycloneDX.

    Ritorna:
    {
        "nome_componente": {
            "version": "...",
            "type": "..."
        }
    }
    """

    with open(
        sbom_path,
        "r",
        encoding="utf-8"
    ) as f:
        sbom = json.load(f)


    components = {}


    for component in sbom.get("components", []):
        name = component.get("name")

        if not name:
            continue


        components[name] = {
            "version": component.get("version"),
            "type": component.get("type")
        }


    return components



def compare_sbom(
    old_sbom_path: str,
    new_sbom_path: str
) -> dict:
    """
    Confronta due SBOM.

    old -> step precedente
    new -> step corrente
    """


    old_components = load_components(
        old_sbom_path
    )

    new_components = load_components(
        new_sbom_path
    )


    added = []
    removed = []
    changed = []

    # nuovi componenti
    for name, info in new_components.items():

        if name not in old_components:

            added.append(
                {
                    "name": name,
                    **info
                }
            )


        else:

            old_version = old_components[name]["version"]
            new_version = info["version"]


            if old_version != new_version:

                changed.append(
                    {
                        "name": name,
                        "old_version": old_version,
                        "new_version": new_version
                    }
                )



    # componenti rimossi
    for name, info in old_components.items():

        if name not in new_components:

            removed.append(
                {
                    "name": name,
                    **info
                }
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