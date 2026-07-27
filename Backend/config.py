# config.py
import os
import tempfile
from dotenv import load_dotenv
from fastapi import FastAPI

load_dotenv()

app = FastAPI(title="SBOM Analyzer Backend")

STORAGE_DIR = os.path.join(tempfile.gettempdir(), "sbom_analyzer_storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

GITHUB_API = "https://api.github.com/repos"
MY_GITHUB_OWNER = os.getenv("MY_GITHUB_OWNER", "RiccardoCortese")
MY_GITHUB_REPO = os.getenv("MY_GITHUB_REPO", "SBOM-Analyzer")
STANDARD_FILE_ANALYZED = None  # Variabile globale per memorizzare il file standard analizzato
GITHUB_REF = "v2.0-tlsassistant"  # Branch o tag da cui partire per le GitHub Actions CAMBIARE AD OGNI BRANCH
