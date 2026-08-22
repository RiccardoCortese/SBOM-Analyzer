import json
import os
import subprocess
import tempfile
from urllib.parse import unquote, urlparse, parse_qs

# SERVE PER SIMULARE L'AGGIORNAMENTO DI UNA DIPENDENZA E CONFRONTARE LE DIPENDENZE RISOLTE

# ============================================================
# PURL
# ============================================================

def get_ecosystem_from_purl(purl):

    if not purl:
        return None

    if purl.startswith("pkg:pypi/"):
        return "pypi"

    if purl.startswith("pkg:npm/"):
        return "npm"
    
    if purl.startswith("pkg:deb/"):
        return "deb"

    return None


def get_package_name_from_purl(purl):

    if not purl:
        return None

    value = purl.split("pkg:", 1)[-1]

    # Rimuove l'ecosistema
    # deb/debian/bsdutils@...
    #       ↓
    # debian/bsdutils@...

    value = value.split("/", 1)[-1]

    # Per Debian il namespace "debian/" fa parte
    # della struttura del PURL, non del nome del pacchetto.

    if value.startswith("debian/"):

        value = value[len("debian/"):]

    value = value.split("@", 1)[0]

    return unquote(value)

# ============================================================
# PYPI
# ============================================================

def resolve_pypi_package(name, version):

    report = {}

    with tempfile.TemporaryDirectory() as temp_dir:

        report_path = os.path.join(temp_dir, "pip_report.json")

        command = [
            "python",
            "-m",
            "pip",
            "install",
            f"{name}=={version}",
            "--dry-run",
            "--ignore-installed",
            "--report",
            report_path
        ]

        try:

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300
            )

        except subprocess.TimeoutExpired:

            return {"success": False, "error": "Timeout durante la risoluzione delle dipendenze."}

        except Exception as e:

            return {"success": False, "error": str(e)}

        if result.returncode != 0:

            return {"success": False, "error": result.stderr}

        if not os.path.exists(report_path):

            return {"success": False, "error": "pip non ha prodotto il report."}

        try:

            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)

        except Exception as e:

            return {"success": False, "error": f"Errore lettura report pip: {e}"}

    packages = {}

    for item in report.get("install", []):

        metadata = item.get("metadata", {})

        package_name = metadata.get("name")
        package_version = metadata.get("version")

        if not package_name:
            continue

        packages[package_name.lower()] = {
            "name": package_name,
            "version": package_version
        }

    return {
        "success": True,
        "packages": packages
    }


# ============================================================
# NPM
# ============================================================

def resolve_npm_package(name, version):

    with tempfile.TemporaryDirectory() as temp_dir:

        package_json = os.path.join(temp_dir, "package.json")

        package_lock = os.path.join(temp_dir, "package-lock.json")

        package_data = {
            "name": "dependency-simulation",
            "version": "1.0.0",
            "private": True,
            "dependencies": {
                name: version
            }
        }

        try:

            with open(package_json, "w", encoding="utf-8") as f:

                json.dump(package_data, f, indent=2)

            command = [
                "npm",
                "install",
                "--package-lock-only",
                "--ignore-scripts",
                "--prefix",
                temp_dir
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300
            )

        except subprocess.TimeoutExpired:

            return {"success": False, "error": "Timeout durante la risoluzione npm."}

        except Exception as e:

            return {"success": False, "error": str(e)}

        if result.returncode != 0:

            return {"success": False,"error": result.stderr}

        if not os.path.exists(package_lock):

            return {"success": False, "error": "npm non ha prodotto package-lock.json."}

        try:

            with open(package_lock, "r", encoding="utf-8") as f:

                lock = json.load(f)

        except Exception as e:

            return {"success": False, "error": f"Errore lettura package-lock: {e}"}

    packages = {}

    for path, data in lock.get("packages", {}).items():

        if not path.startswith("node_modules/"):
            continue

        package_name = path[len("node_modules/"):]

        packages[package_name.lower()] = {
            "name": package_name,
            "version": data.get("version")
        }

    return {
        "success": True,
        "packages": packages
    }
    
# ============================================================
# DEBIAN
# ============================================================

def resolve_deb_package(name, version, purl, resolve_versions=False):

    try:

        # ----------------------------------------------------
        # Informazioni dal PURL
        # ----------------------------------------------------

        parsed = urlparse(purl)
        query = parse_qs(parsed.query)

        arch = query.get("arch", ["amd64"])[0]
        distro = query.get("distro", ["debian-13"])[0]
        epoch = query.get("epoch", [None])[0]

        # ----------------------------------------------------
        # Release Debian
        # ----------------------------------------------------

        if distro.startswith("debian-"):

            release = distro.replace("debian-", "").split(".")[0]

        else:

            return {
                "success": False,
                "error": f"Distribuzione Debian non riconosciuta: {distro}"
            }

        # ----------------------------------------------------
        # Versione completa
        # ----------------------------------------------------

        full_version = version

        if epoch and not version.startswith(f"{epoch}:"):

            full_version = f"{epoch}:{version}"

        # ----------------------------------------------------
        # Recupera SOLO le dipendenze
        # ----------------------------------------------------

        command = [
            "docker",
            "run",
            "--rm",
            f"debian:{release}",
            "bash",
            "-c",
            (
                "set -e && "
                "apt-get update -qq && "
                f"apt-cache depends "
                f"--recurse "
                f"--no-suggests "
                f"--no-recommends "
                f"--no-conflicts "
                f"--no-breaks "
                f"--no-replaces "
                f"--no-enhances "
                f"{name}:{arch}={full_version}"
            )
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300
        )

    except subprocess.TimeoutExpired:

        return {
            "success": False,
            "error": "Timeout durante la risoluzione Debian."
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }

    # --------------------------------------------------------
    # Errore
    # --------------------------------------------------------

    if result.returncode != 0:

        return {
            "success": False,
            "error": (
                f"Impossibile risolvere "
                f"{name}={full_version}: "
                f"{result.stderr}"
            )
        }

    # --------------------------------------------------------
    # Parsing
    # --------------------------------------------------------

    packages = {}

    for line in result.stdout.splitlines():

        line = line.strip()

        if not line:

            continue

        # apt-cache produce righe tipo:
        #
        # bsdutils
        #   Depends: libc6
        #   Depends: libsystemd0
        #
        # oppure:
        #
        #   PreDepends: libc6

        if ":" not in line:

            # Il primo elemento è il pacchetto principale
            if not packages:

                packages[name.lower()] = {
                    "name": name,
                    "version": full_version
                }

            continue

        dependency = line.split(":", 1)[1].strip()

        if not dependency:

            continue

        # ----------------------------------------------------
        # Alternative
        # ----------------------------------------------------

        dependency = dependency.split("|", 1)[0].strip()

        # ----------------------------------------------------
        # Rimuove eventuali vincoli
        # ----------------------------------------------------

        dependency_name = dependency.split("(", 1)[0].strip()

        # ----------------------------------------------------
        # Rimuove eventuale architettura
        # ----------------------------------------------------

        dependency_name = dependency_name.split(":", 1)[0]

        if not dependency_name:

            continue

        packages.setdefault(
            dependency_name.lower(),
            {
                "name": dependency_name,
                "version": None
            }
        )
    
    if resolve_versions:

        for package_name, package_data in packages.items():

            if package_name == name.lower():
                continue

            policy_command = [
                "docker",
                "run",
                "--rm",
                f"debian:{release}",
                "bash",
                "-c",
                (
                    "apt-get update -qq >/dev/null 2>&1 && "
                    f"apt-cache policy {package_data['name']}:{arch}"
                )
            ]

            policy_result = subprocess.run(
                policy_command,
                capture_output=True,
                text=True,
                timeout=300
            )

            if policy_result.returncode != 0:
                continue

            for policy_line in policy_result.stdout.splitlines():

                policy_line = policy_line.strip()

                if policy_line.startswith("Candidate:"):

                    candidate = policy_line.split(":", 1)[1].strip()

                    if candidate != "(none)":
                        package_data["version"] = candidate

                    break

    print(
        f"[DEBUG DEB] {name}={full_version} "
        f"risolte {len(packages)} dipendenze:",
        flush=True
    )

    for package_name, package_data in sorted(packages.items()):

        print(f"{package_name} -> {package_data['version']}", flush=True)

    return {
        "success": True,
        "packages": packages
    }
# ============================================================
# RISOLUZIONE
# ============================================================

def resolve_target_package(purl, version, resolve_versions=False):

    ecosystem = get_ecosystem_from_purl(purl)
    name = get_package_name_from_purl(purl)

    if not ecosystem:

        return {"success": False, "error": f"Ecosistema non supportato: {purl}"}

    if not name:

        return {"success": False, "error": f"Nome pacchetto non ricavabile dal PURL: {purl}"}

    if ecosystem == "pypi":

        return resolve_pypi_package(name, version)

    if ecosystem == "npm":

        return resolve_npm_package(name, version)

    if ecosystem == "deb":

        return resolve_deb_package(name, version, purl, resolve_versions=resolve_versions)
    
    return {"success": False, "error": f"Ecosistema non supportato: {ecosystem}"}

# ============================================================
# SBOM ATTUALE
# ============================================================

def get_current_packages(sbom_file, ecosystem):

    try:

        with open(sbom_file, "r", encoding="utf-8") as f:
            sbom = json.load(f)

    except Exception:

        return {}

    packages = {}

    for component in sbom.get("components", []):

        name = component.get("name")
        version = component.get("version")
        purl = component.get("purl")

        if not name or not purl:
            continue

        component_ecosystem = get_ecosystem_from_purl(purl)

        if component_ecosystem != ecosystem:
            continue

        packages[name.lower()] = {
            "name": name,
            "version": version,
            "purl": purl
        }

    return packages

# ============================================================
# CONFRONTO
# ============================================================

def compare_dependencies(sbom_packages, current_dependencies, target_dependencies, target_name):

    unchanged = []
    changed = []
    added = []
    removed = []

    target_name = target_name.lower()
    
    # ========================================================
    # Pacchetto target che viene aggiornato
    # ========================================================

    if target_name in sbom_packages:

        current_version = sbom_packages[target_name].get("version")
        target_version = target_dependencies.get(target_name, {}).get("version")

        if current_version != target_version:

            changed.append({
                "name": sbom_packages[target_name].get(
                    "name",
                    target_name
                ),
                "from": current_version,
                "to": target_version
            })

    # ========================================================
    # Dipendenze attuali
    # ========================================================

    current_dependency_names = set(current_dependencies.keys())

    target_dependency_names = set(target_dependencies.keys())

    # ========================================================
    # Dipendenze presenti in entrambe
    # ========================================================

    for name in sorted(current_dependency_names & target_dependency_names):

        if name == target_name:
            continue

        current_version = (sbom_packages.get(name, {}).get("version"))

        target_version = (target_dependencies[name].get("version"))

        if current_version == target_version:

            unchanged.append({
                "name": sbom_packages
                .get(name, {})
                .get("name", name),
                "version": current_version
            })

        else:

            changed.append({
                "name": sbom_packages
                .get(name, {})
                .get("name", name),
                "from": current_version,
                "to": target_version
            })

    # ========================================================
    # Nuove dipendenze
    # ========================================================

    for name in sorted(target_dependency_names - current_dependency_names):

        if name == target_name:
            continue

        dependency = target_dependencies[name]

        added.append({
            "name": dependency.get("name", name),
            "version": dependency.get("version")
        })

    # ========================================================
    # Dipendenze rimosse
    # ========================================================

    for name in sorted(current_dependency_names - target_dependency_names):

        if name == target_name:
            continue

        dependency = sbom_packages.get(name)

        if not dependency:
            continue

        removed.append({
            "name": dependency.get("name", name),
            "version": dependency.get("version")
        })

    # ========================================================
    # Tutti gli altri pacchetti SBOM rimangono invariati
    # ========================================================

    affected_names = (current_dependency_names | target_dependency_names)

    for name, package in sbom_packages.items():

        if name == target_name:
            continue

        if name in affected_names:
            continue

        unchanged.append({
            "name": package.get("name", name),
            "version": package.get("version")
        })
        
    print(
        f"[DEBUG COMPARE] "
        f"SBOM={len(sbom_packages)} "
        f"current_deps={len(current_dependencies)} "
        f"target_deps={len(target_dependencies)} "
        f"unchanged={len(unchanged)} "
        f"changed={len(changed)} "
        f"added={len(added)} "
        f"removed={len(removed)}",
        flush=True
    )

    return {
        "unchanged": unchanged,
        "changed": changed,
        "added": added,
        "removed": removed
    }
# ============================================================
# SIMULAZIONE
# ============================================================

def simulate_dependency_update(purl, current_version, target_version, sbom_file):

    ecosystem = get_ecosystem_from_purl(purl)
    
    if not ecosystem:

        return {
            "success": False,
            "error": f"Ecosistema non supportato: {purl}"
        }
    
    current_packages = get_current_packages(sbom_file, ecosystem)

    if not current_packages:

        return {"success": False, "error": "Nessun componente trovato nello SBOM."}

    package_name = get_package_name_from_purl(purl)

    # --------------------------------------------------------
    # Risoluzione versione ATTUALE
    # --------------------------------------------------------

    # Risolvo SOLO la struttura delle dipendenze attuali
    current_result = resolve_target_package(
        purl,
        current_version,
        resolve_versions=False
    )

    if not current_result["success"]:
        return {
            "success": False,
            "error": (
                "Impossibile risolvere la versione attuale: "
                + current_result.get("error", "errore sconosciuto")
            )
        }

    current_dependencies = current_result["packages"]

    # --------------------------------------------------------
    # Risoluzione versione TARGET
    # --------------------------------------------------------

    # Risolvo struttura + versioni candidate
    target_result = resolve_target_package(
        purl,
        target_version,
        resolve_versions=True
    )

    if not target_result["success"]:
        return target_result

    target_dependencies = target_result["packages"]

    # --------------------------------------------------------
    # Confronto
    # --------------------------------------------------------

    comparison = compare_dependencies(
        current_packages,
        current_dependencies,
        target_dependencies,
        package_name
    )
    return {
        "success": True,
        "component": package_name,
        "current_version": current_version,
        "target_version": target_version,
        "ecosystem": ecosystem,
        **comparison
    }