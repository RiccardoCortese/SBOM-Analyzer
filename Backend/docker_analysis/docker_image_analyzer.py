import os
import json
import subprocess

from utils.tools import get_trivy_path


class DockerImageAnalyzer:
    def __init__(self, output_dir=None):
        self.output_dir = output_dir
        self.trivy_path = get_trivy_path()

    def generate_sbom(self, image_tag: str, step_index: int) -> str:
        sbom_path = os.path.join(self.output_dir, f"step_{step_index}_sbom.json")

        command = [
            self.trivy_path,
            "image",
            "--format",
            "cyclonedx",
            "--output",
            sbom_path,
            image_tag
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Errore Trivy per {image_tag}:\n{result.stderr}"
            )

        return sbom_path

    def load_sbom(self, sbom_path: str) -> dict:
        with open(sbom_path, "r", encoding="utf-8") as f:
            return json.load(f)