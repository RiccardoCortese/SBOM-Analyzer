import json
import os
import subprocess
import tempfile
from unittest import result
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
    
    if purl.startswith("pkg:deb/"): # sia per Debian che per Ubuntu (per capirlo bisogna leggere il parametro "distro" del PURL)
        return "deb"
    
    if purl.startswith("pkg:maven/"):
        return "maven"

    return None


def get_package_name_from_purl(purl):

    if not purl:
        return None

    value = purl.split("pkg:", 1)[-1]
    
    if value.startswith("maven/"):

        value = value[len("maven/"):]

        value = value.split("@", 1)[0]

        parts = value.split("/")

        if len(parts) < 2:
            return None

        group_id = ".".join(parts[:-1])
        artifact_id = parts[-1]

        return f"{group_id}:{artifact_id}"

    # Rimuove l'ecosistema
    # deb/debian/bsdutils@...
    #       ↓
    # debian/bsdutils@...

    value = value.split("/", 1)[-1]

    # Per Debian il namespace "debian/" o "ubuntu/" fa parte
    # della struttura del PURL, non del nome del pacchetto.

    if "/" in value:

        value = value.split("/", 1)[1]

    # Rimuove versione

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
# MAVEN
# ============================================================

def resolve_maven_package(name, version):

    with tempfile.TemporaryDirectory() as temp_dir:

        pom_path = os.path.join(temp_dir, "pom.xml")

        # ----------------------------------------------------
        # PURL Maven:
        #
        # pkg:maven/junit/junit@4.13.1
        #
        # name = junit:junit
        # ----------------------------------------------------

        if ":" not in name:

            return {
                "success": False,
                "error": f"Nome Maven non valido: {name}"
            }

        group_id, artifact_id = name.split(":", 1)

        pom = f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         https://maven.apache.org/xsd/maven-4.0.0.xsd">

    <modelVersion>4.0.0</modelVersion>

    <groupId>simulation</groupId>
    <artifactId>dependency-simulation</artifactId>
    <version>1.0</version>

    <dependencies>

        <dependency>
            <groupId>{group_id}</groupId>
            <artifactId>{artifact_id}</artifactId>
            <version>{version}</version>
        </dependency>

    </dependencies>

</project>
"""

        try:

            with open(
                pom_path,
                "w",
                encoding="utf-8"
            ) as f:

                f.write(pom)

            command = [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{temp_dir}:/simulation",
                "maven:3.9-eclipse-temurin-17",
                "mvn",
                "-f",
                "/simulation/pom.xml",
                "dependency:tree",
                "-DoutputType=text",
                "-Dverbose=false",
                "-Dscope=runtime"
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
                "error": "Timeout durante la risoluzione Maven."
            }

        except Exception as e:

            return {
                "success": False,
                "error": str(e)
            }

    if result.returncode != 0:

        return {
            "success": False,
            "error": (
                "Maven non è riuscito a risolvere "
                f"{name}={version}: "
                f"{result.stderr}"
            )
        }

    # ========================================================
    # PARSING ALBERO MAVEN
    # ========================================================

    packages = {}

    # Il pacchetto che stiamo simulando deve esserci SEMPRE
    packages[name.lower()] = {
        "name": name,
        "version": version
    }

    for raw_line in result.stdout.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        # Rimuove [INFO]
        if line.startswith("[INFO]"):

            line = line[len("[INFO]"):].strip()

        # ----------------------------------------------------
        # Ignora intestazioni Maven
        # ----------------------------------------------------

        if line.startswith("simulation:dependency-simulation:"):
            continue

        if line.startswith("BUILD "):
            continue

        if line.startswith("Total time:"):
            continue

        if line.startswith("Finished at:"):
            continue

        if line.startswith("Downloaded from"):
            continue

        if line.startswith("Downloading from"):
            continue

        # ----------------------------------------------------
        # Manteniamo solamente le righe dell'albero
        #
        # +- junit:junit:jar:4.13.1:compile
        # \- org.hamcrest:hamcrest-core:jar:1.3:compile
        # ----------------------------------------------------

        if not (
            line.startswith("+-")
            or line.startswith("\\-")
        ):
            continue

        dependency = line[2:].strip()

        parts = dependency.split(":")

        # Maven:
        #
        # groupId
        # artifactId
        # type
        # version
        # scope
        #
        # Esempio:
        #
        # junit:junit:jar:4.13.1:compile

        if len(parts) < 4:
            continue

        group_id = parts[0]
        artifact_id = parts[1]
        package_version = parts[3]

        if not group_id:
            continue

        if not artifact_id:
            continue

        if not package_version:
            continue

        package_name = f"{group_id}:{artifact_id}"

        # Evita di inserire il progetto Maven
        if package_name == "simulation:dependency-simulation":
            continue

        packages[package_name.lower()] = {
            "name": package_name,
            "version": package_version
        }

    # ========================================================
    # VALIDAZIONE
    # ========================================================

    if name.lower() not in packages:

        return {
            "success": False,
            "error": (
                f"Maven non ha restituito il pacchetto "
                f"{name}={version}."
            )
        }

    print(
        f"[DEBUG MAVEN] {name}={version} "
        f"risolte {len(packages)} dipendenze:",
        flush=True
    )

    for package_name, package_data in sorted(packages.items()):

        print(
            f"{package_data['name']} -> "
            f"{package_data['version']}",
            flush=True
        )

    return {
        "success": True,
        "packages": packages
    }
# ============================================================
# DISTRIBUZIONE DEB
# ============================================================

def get_deb_docker_image(distro):

    if not distro:
        return None

    # Debian
    if distro.startswith("debian-"):

        release = distro[len("debian-"):]

        return f"debian:{release}"

    # Ubuntu
    if distro.startswith("ubuntu-"):

        release = distro[len("ubuntu-"):]

        return f"ubuntu:{release}"

    return None

# ============================================================
# DEBIAN e UBUNTU
# ============================================================
def get_deb_distribution_info(purl):
    """
    Ricava distribuzione e release dal PURL Debian/Ubuntu.

    Esempi:
    pkg:deb/debian/bsdutils@...?...&distro=debian-13
    pkg:deb/ubuntu/bind9-libs@...?...&distro=ubuntu-22.04
    """

    parsed = urlparse(purl)
    query = parse_qs(parsed.query)

    distro = query.get("distro", [None])[0]

    if not distro:
        return None, None

    if distro.startswith("debian-"):
        return "debian", distro.replace("debian-", "", 1)

    if distro.startswith("ubuntu-"):
        return "ubuntu", distro.replace("ubuntu-", "", 1)

    return None, None

def resolve_deb_package(name, version, purl, resolve_versions=False):

    try:

        # ----------------------------------------------------
        # Informazioni dal PURL
        # ----------------------------------------------------

        parsed = urlparse(purl)
        query = parse_qs(parsed.query)

        arch = query.get("arch", ["amd64"])[0]
        epoch = query.get("epoch", [None])[0]

        distribution, release = get_deb_distribution_info(purl)

        if not distribution or not release:

            return {
                "success": False,
                "error": (
                    f"Distribuzione non riconosciuta dal PURL: "
                    f"{purl}"
                )
            }

        # ----------------------------------------------------
        # Versione completa
        # ----------------------------------------------------

        full_version = version

        if epoch and not version.startswith(f"{epoch}:"):
            full_version = f"{epoch}:{version}"

        image = f"{distribution}:{release}"

        print(
            f"[DEBUG DEB] "
            f"distribution={distribution} "
            f"release={release} "
            f"package={name} "
            f"version={full_version} "
            f"arch={arch}",
            flush=True
        )

        # ----------------------------------------------------
        # Risoluzione dipendenze
        # ----------------------------------------------------

        command = [
            "docker",
            "run",
            "--rm",
            image,
            "bash",
            "-c",
            (
                "set -e; "
                "export DEBIAN_FRONTEND=noninteractive; "
                "apt-get update -qq >/dev/null 2>&1; "
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

        print(
            f"[DEBUG DEB] Avvio risoluzione: {' '.join(command)}",
            flush=True
        )

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )

    except subprocess.TimeoutExpired:

        return {
            "success": False,
            "error": (
                f"Timeout durante la risoluzione "
                f"di {name}={full_version}"
            )
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
                f"{result.stderr.strip()}"
            )
        }

    # --------------------------------------------------------
    # Parsing
    # --------------------------------------------------------

    packages = {
        name.lower(): {
            "name": name,
            "version": full_version
        }
    }

    for line in result.stdout.splitlines():

        line = line.strip()

        if not line:
            continue

        if ":" not in line:
            continue

        dependency = line.split(":", 1)[1].strip()

        if not dependency:
            continue

        # ----------------------------------------------------
        # Alternative
        # ----------------------------------------------------

        dependency = dependency.split("|", 1)[0].strip()

        # ----------------------------------------------------
        # Rimuove vincoli di versione
        # ----------------------------------------------------

        dependency_name = dependency.split("(", 1)[0].strip()

        # ----------------------------------------------------
        # Rimuove architettura
        # ----------------------------------------------------

        dependency_name = dependency_name.split(":", 1)[0].strip()

        if not dependency_name:
            continue
        
        if dependency_name.startswith("<") and dependency_name.endswith(">"):
            continue

        packages.setdefault(
            dependency_name.lower(),
            {
                "name": dependency_name,
                "version": None
            }
        )

    # --------------------------------------------------------
    # Risoluzione versioni
    # --------------------------------------------------------

    if resolve_versions:

        print(
            f"[DEBUG DEB] Risoluzione versioni di "
            f"{len(packages)} pacchetti...",
            flush=True
        )

        # --------------------------------------------------------
        # Costruisce un unico comando da eseguire nel container
        # --------------------------------------------------------

        policy_commands = []

        for package_name, package_data in packages.items():

            if package_name == name.lower():
                continue

            policy_commands.append(
                f"echo '### {package_name}'; "
                f"apt-cache policy "
                f"{package_data['name']}:{arch}"
            )

        if policy_commands:

            policy_command = [
                "docker",
                "run",
                "--rm",
                image,
                "bash",
                "-c",
                (
                    "set -e; "
                    "export DEBIAN_FRONTEND=noninteractive; "
                    "apt-get update -qq >/dev/null 2>&1; "
                    + " ; ".join(policy_commands)
                )
            ]

            try:

                policy_result = subprocess.run(
                    policy_command,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if policy_result.returncode != 0:

                    print(
                        f"[DEBUG DEB] policy FALLITA "
                        f"{package_data['name']}:{arch}",
                        flush=True
                    )

                    print(
                        f"[DEBUG DEB] stderr: {policy_result.stderr}",
                        flush=True
                    )


                print(
                    f"[DEBUG DEB] policy {package_data['name']}:",
                    flush=True
                )

                print(
                    policy_result.stdout,
                    flush=True
                )

            except subprocess.TimeoutExpired:

                print(
                    "[DEBUG DEB] Timeout durante "
                    "la risoluzione delle versioni.",
                    flush=True
                )

                policy_result = None

            if policy_result and policy_result.returncode == 0:

                current_package = None

                for line in policy_result.stdout.splitlines():

                    line = line.strip()

                    if line.startswith("### "):

                        current_package = line[4:].strip()
                        continue

                    if (
                        current_package
                        and line.startswith("Candidate:")
                    ):

                        candidate = line.split(
                            ":",
                            1
                        )[1].strip()

                        if candidate != "(none)":

                            packages[current_package]["version"] = candidate

                        current_package = None

        print(
            "[DEBUG DEB] Risoluzione versioni completata.",
            flush=True
        )

    print(
        f"[DEBUG DEB] {name}={full_version} "
        f"risolte {len(packages)} dipendenze:",
        flush=True
    )

    for package_name, package_data in sorted(packages.items()):

        print(
            f"{package_name} -> "
            f"{package_data['version']}",
            flush=True
        )

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
    
    if ecosystem == "maven":

        return resolve_maven_package(name, version)
    
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

    if target_name in current_dependencies:

        current_version = (
            current_dependencies
            .get(target_name, {})
            .get("version")
        )

        target_version = (
            target_dependencies
            .get(target_name, {})
            .get("version")
        )

        if (
            current_version is not None
            and target_version is not None
            and current_version != target_version
        ):

            changed.append({
                "name": current_dependencies[target_name].get(
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

        # La versione attuale deve arrivare dalla risoluzione
        # della versione corrente, NON dallo SBOM.
        current_version = (
            current_dependencies
            .get(name, {})
            .get("version")
        )

        target_version = (
            target_dependencies
            .get(name, {})
            .get("version")
        )

        package_name = (
            current_dependencies
            .get(name, {})
            .get("name", name)
        )

        # Se Maven non ha restituito una versione,
        # non possiamo fare un confronto affidabile.
        if current_version is None or target_version is None:
            continue

        if current_version == target_version:

            unchanged.append({
                "name": package_name,
                "version": current_version
            })

        else:

            changed.append({
                "name": package_name,
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

        version = dependency.get("version")

        if version is None:
            continue

        added.append({
            "name": dependency.get("name", name),
            "version": version
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