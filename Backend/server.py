from fastapi import FastAPI, UploadFile, File, HTTPException
import json
import subprocess
from dotenv import load_dotenv
import os
import re # libreria regex per estrarre informazioni dai nomi dei file
import requests
from functools import lru_cache # libreria per caching delle chiamate alle API esterne 

load_dotenv()  # Carica le variabili d'ambiente dal file .env

app = FastAPI(title="TLSAssistant Dependency Analyzer Backend")

GITHUB_API = "https://api.github.com/repos" # URL base per le API di GitHub

# ============================================================
# GITHUB TOKEN, se presente, viene utilizzato per autenticare le richieste alle API di GitHub
# ============================================================
def github_headers():
    token = os.getenv("GITHUB_TOKEN")

    if token:
        return {"Authorization": f"Bearer {token}"}

    return {}

# ============================================================
# GITHUB HELPERS, per estrarre informazioni dai repository GitHub
# ============================================================

def parse_github_url(url: str) -> str:
    """Estrae URL GitHub normalizzato"""

    if not url or not isinstance(url, str):
        return "N/A"

    match = re.search(
        r"github\.com/([^/]+)/([^/?#]+)",
        url
    )

    if not match:
        return "N/A"

    owner = match.group(1)
    repo = match.group(2).replace(".git", "")

    return f"https://github.com/{owner}/{repo}"


@lru_cache(maxsize=128) # Cache per migliorare le prestazioni delle chiamate ripetute
def fetch_github_metadata(repo_url: str) -> dict:
    """Recupera metadati GitHub"""

    if repo_url == "N/A":
        return {}

    try:
        parts = repo_url.rstrip("/").split("/")

        owner = parts[-2]
        repo = parts[-1]

        response = requests.get(
            f"{GITHUB_API}/{owner}/{repo}",
            headers=github_headers(),
            timeout=5
        )

        if response.status_code != 200:
            return {}

        data = response.json()

        return {
            "language": data.get("language"),
            "stars": data.get("stargazers_count"),
            "default_branch": data.get("default_branch"),
            "description": data.get("description")
        }

    except Exception:
        return {}


# ============================================================
# PYPI HELPERS, per estrarre informazioni dai pacchetti Python
# ============================================================

@lru_cache(maxsize=128)
def fetch_pypi_metadata(package_name: str) -> dict:
    """Recupera repo GitHub e metadati da PyPI"""

    try:
        response = requests.get(
            f"https://pypi.org/pypi/{package_name}/json",
            timeout=5
        )

        if response.status_code != 200:
            return {}

        info = response.json().get("info", {})

        github_repo = "N/A"

        project_urls = info.get("project_urls", {})

        for value in project_urls.values():
            if value and "github.com" in value.lower():
                github_repo = parse_github_url(value)
                break

        if github_repo == "N/A":
            homepage = info.get("home_page", "")

            if homepage and "github.com" in homepage.lower():
                github_repo = parse_github_url(homepage)

        return {
            "github_repo": github_repo,
            "license": info.get("license"),
            "summary": info.get("summary")
        }

    except Exception:
        return {}


# ============================================================
# VERSION EXTRACTION, per estrarre la versione dai nomi dei file
# ============================================================

def extract_version_from_filename(filename: str) -> str:
    patterns = [
        r'[_\-]v?(\d+\.\d+\.\d+(?:\.\d+)?)',
        r'[_\-]v?(\d+\.\d+)'
    ]

    for pattern in patterns:
        match = re.search(pattern, filename)

        if match:
            return match.group(1)

    return "unknown"


# ============================================================
# PURL, per costruire il Package URL (PURL) standardizzato
# ============================================================

def build_purl(dep_type: str, name: str, version: str | None = None):

    if dep_type == "pip":
        if version:
            return f"pkg:pypi/{name}@{version}"
        return f"pkg:pypi/{name}"

    if dep_type == "apt":
        return f"pkg:deb/debian/{name}"

    if dep_type in ["compile_maven", "maven"]:
        return f"pkg:maven/{name}"

    if version:
        return f"pkg:generic/{name}@{version}"

    return f"pkg:generic/{name}"


# ============================================================
# COMPONENT TYPE, per classificare il tipo di componente in base al tipo di dipendenza
# ============================================================

def classify_component(dep_type: str):

    mapping = {
        "pip": "library",
        "apt": "system-package",
        "git": "application",
        "git-submodule": "application",
        "pkg": "binary-package",
        "zip": "binary-package",
        "file": "data-file",
        "cfg": "configuration",
        "compile_maven": "build-tool",
        "python3": "script"
    }

    return mapping.get(dep_type, "unknown")


# ============================================================
# EXTRACTION, per estrarre nome e versione dai dati delle dipendenze
# ============================================================

def extract_name_and_version(item):

    dep_type = item.get("type", "N/A")
    value = item.get("url") or item.get("path") or ""

    name = value
    version = "unknown"
    language = None

    if dep_type == "pip":

        language = "Python"

        if "==" in value:
            name, version = value.split("==", 1)

        elif value.startswith("-r"):
            req_file = value.replace("-r", "").strip()
            name = f"Requirements File: {req_file}"
            version = "manifest"

    elif dep_type == "apt":

        name = value
        language = "System"

    elif dep_type in ["compile_maven", "maven"]:

        language = "Java"

    elif dep_type in ["git", "git-submodule"]:

        repo = parse_github_url(value)

        if repo != "N/A":
            name = repo.split("/")[-1]

    elif dep_type in ["pkg", "zip", "file"]:

        filename = value.split("/")[-1]

        name = re.sub(
            r'(\.zip|\.deb|\.tar\.gz|\.tgz)$',
            '',
            filename
        )

        version = extract_version_from_filename(filename)

    purl = build_purl(
        dep_type,
        name,
        None if version == "unknown" else version
    )

    return name, version, purl, language


# ============================================================
# API
# ============================================================

@app.post("/analyze")
async def analyze_dependencies(file: UploadFile = File(...)):

    try:

        contents = await file.read()

        dependencies = json.loads(contents)

        if not isinstance(dependencies, list):
            raise HTTPException(
                status_code=400,
                detail="Il file JSON deve contenere una lista di oggetti."
            )

        extracted_data = []

        python_packages = ""

        git_repositories = []

        for item in dependencies:

            dep_type = item.get("type", "N/A")

            url_val = item.get("url") or item.get("path") or ""

            name, version, purl, language = extract_name_and_version(item)

            component_type = classify_component(dep_type)

            github_repo = parse_github_url(item.get("url", ""))

            license_name = "N/A"
            stars = None
            default_branch = None
            description = None

            # ------------------------------------------
            # PIP PACKAGE, per estrarre informazioni dai pacchetti Python tramite PyPI
            # ------------------------------------------

            if dep_type == "pip" and "==" in url_val:

                pypi_data = fetch_pypi_metadata(name)

                if pypi_data:

                    if github_repo == "N/A":
                        github_repo = pypi_data.get(
                            "github_repo",
                            "N/A"
                        )

                    license_name = pypi_data.get(
                        "license",
                        "N/A"
                    )

            # ------------------------------------------
            # GITHUB METADATA
            # ------------------------------------------

            if github_repo != "N/A":

                github_data = fetch_github_metadata(
                    github_repo
                )

                if github_data:

                    language = (
                        github_data.get("language")
                        or language
                    )

                    stars = github_data.get("stars")

                    default_branch = github_data.get(
                        "default_branch"
                    )

                    description = github_data.get(
                        "description"
                    )

            extracted_data.append({
                "type": dep_type,
                "component_type": component_type,
                "name": name,
                "version": version,
                "purl": purl,
                "language": language,
                "github_repo": github_repo,
                "license": license_name,
                "stars": stars,
                "default_branch": default_branch,
                "description": description
            })

            # ------------------------------------------
            # TRIVY INPUT
            # ------------------------------------------

            if dep_type == "pip" and "==" in url_val:
                python_packages += f"{url_val}\n"

            # ------------------------------------------
            # UNIQUE REPOS
            # ------------------------------------------

            if (
                github_repo != "N/A"
                and github_repo not in git_repositories
            ):
                git_repositories.append(github_repo)

        # ====================================================
        # TRIVY
        # ====================================================

        trivy_report = (
            "Nessun pacchetto Python specifico "
            "con versione trovato da scansionare."
        )

        if python_packages:

            temp_file = "temp_tlsassistant_req.txt"

            with open(
                temp_file,
                "w",
                encoding="utf-8"
            ) as f:
                f.write(python_packages)

            try:

                result = subprocess.run(
                    [
                        "trivy",
                        "fs",
                        "--format",
                        "table",
                        temp_file
                    ],
                    capture_output=True,
                    text=True,
                    check=True
                )

                trivy_report = result.stdout

            except Exception as e:

                trivy_report = (
                    f"Errore durante "
                    f"l'esecuzione di Trivy: {str(e)}"
                )

            finally:

                if os.path.exists(temp_file):
                    os.remove(temp_file)

        return {
            "status": "success",
            "count": len(extracted_data),
            "dependencies": extracted_data,
            "detected_git_repos": git_repositories,
            "vulnerabilities_report": trivy_report
        }

    except Exception as e:

        raise HTTPException(
            status_code=400,
            detail=f"Errore nell'elaborazione del JSON: {str(e)}"
        )


if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000
    )

