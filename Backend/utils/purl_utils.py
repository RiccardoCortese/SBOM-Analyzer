from urllib.parse import parse_qsl, urlencode
import copy


def normalize_purl(purl):
    """
    Rimuove esclusivamente il qualificatore type=jar dai PURL Maven.
    Mantiene invariati gli altri qualificatori.
    """
    if not isinstance(purl, str) or not purl.startswith("pkg:maven/"):
        return purl

    if "?" not in purl:
        return purl

    base, query = purl.split("?", 1)
    qualifiers = parse_qsl(query, keep_blank_values=True)

    qualifiers = [
        (key, value)
        for key, value in qualifiers
        if not (key.lower() == "type" and value.lower() == "jar")
    ]

    if not qualifiers:
        return base

    qualifiers.sort()
    return f"{base}?{urlencode(qualifiers)}"


def normalize_sbom_purls(sbom):
    """
    Normalizza l'intero SBOM CycloneDX:
    - purl dei componenti
    - bom-ref dei componenti
    - ref e dependsOn delle dipendenze
    - ref dei componenti interessati dalle vulnerabilità

    Non deduplica i componenti e non modifica gli altri metadati.
    Restituisce una copia dello SBOM.
    """
    sbom = copy.deepcopy(sbom)

    # Normalizza purl e bom-ref di tutti i componenti
    for component in sbom.get("components", []):
        if component.get("purl"):
            component["purl"] = normalize_purl(component["purl"])

        if component.get("bom-ref"):
            component["bom-ref"] = normalize_purl(
                component["bom-ref"]
            )

    # Normalizza anche eventuali componenti annidati
    def normalize_nested_components(components):
        for component in components:
            if component.get("purl"):
                component["purl"] = normalize_purl(
                    component["purl"]
                )

            if component.get("bom-ref"):
                component["bom-ref"] = normalize_purl(
                    component["bom-ref"]
                )

            normalize_nested_components(
                component.get("components", [])
            )

    normalize_nested_components(sbom.get("components", []))

    # Normalizza i riferimenti del grafo delle dipendenze
    for dependency in sbom.get("dependencies", []):
        if dependency.get("ref"):
            dependency["ref"] = normalize_purl(
                dependency["ref"]
            )

        if "dependsOn" in dependency:
            dependency["dependsOn"] = [
                normalize_purl(ref)
                for ref in dependency["dependsOn"]
            ]

    # Normalizza i riferimenti nelle vulnerabilità
    for vulnerability in sbom.get("vulnerabilities", []):
        for affected in vulnerability.get("affects", []):
            if affected.get("ref"):
                affected["ref"] = normalize_purl(
                    affected["ref"]
                )

    return sbom