# Server per ricercare possibili artifacts malevoli in un'immagine Docker

from dataclasses import dataclass
import re
import json
import shlex
from docker_analysis.docker_step_analyzer import DockerStep


@dataclass
class DockerArtifactCandidate:
    """
    Rappresenta un possibile file/binario
    introdotto durante il build Docker.
    """

    step_index: int

    artifact_type: str
    # copy, download, install, compile...

    source: str | None

    destination: str | None
    
    source_type: str #local, stage, download
    
    reason: str


class DockerArtifactDetector:
    """
    Analizza gli step Docker e cerca istruzioni
    che possono introdurre nuovi file nell'immagine.
    """
    def _extract_urls(self, tokens: list[str]) -> list[str]:
        return [
            token
            for token in tokens
            if token.startswith(("http://", "https://"))
        ]


    def _extract_packages(
        self,
        tokens: list[str],
        install_keyword: str
    ) -> list[str]:

        packages = []

        try:
            idx = tokens.index(install_keyword)
        except ValueError:
            return packages

        for token in tokens[idx + 1:]:

            if token == "&&":
                break

            if token.startswith("-"):
                continue

            packages.append(token)

        return packages

        

    def analyze( self, steps: list[DockerStep]) -> list[DockerArtifactCandidate]:

        artifacts = []

        for step in steps:

            # Divisione tra COPY/ADD e RUN perchè hanno comportamenti diversi
            if step.instruction in {
                "COPY",
                "ADD"
            }:
                artifacts.extend(
                    self._analyze_copy(step)
                )

            elif step.instruction == "RUN":

                artifacts.extend(
                    self._analyze_run(step)
                )

        return artifacts


    def _clean_argument(self, parts):
        return [
            p for p in parts
            if not p.startswith("-") and not p.startswith("--")
        ]

    def _analyze_copy( self, step: DockerStep) -> list[DockerArtifactCandidate]:

        command = step.command.strip()

        artifacts = []

        source_type = "local"

        # Gestione COPY --from=stage
        if command.startswith("--from="):

            source_type = "stage"

            parts = command.split()

            parts = [
                p for p in parts
                if not p.startswith("--")
            ]

            if len(parts) >= 2:

                artifacts.append(
                    DockerArtifactCandidate(
                        step_index=step.index,
                        artifact_type="copied_file",
                        source=parts[0],
                        destination=parts[-1],
                        source_type=source_type,
                        reason="COPY from previous build stage"
                    )
                )
                
            return artifacts

        # Gestione COPY JSON:
        #
        # COPY ["a", "b", "dest"]
        #
        if command.startswith("["):

            try:
                args = json.loads(command)

                for src in args[:-1]:

                    artifacts.append(
                        DockerArtifactCandidate(
                            step_index=step.index,
                            artifact_type="copied_file",
                            source=src,
                            destination=args[-1],
                            source_type="local",
                            reason="COPY introduces external file"
                        )
                    )

                return artifacts

            except Exception:
                pass

        # COPY normale
        parts = command.split()

        # rimuove opzioni tipo:
        # --chown=1000:1000
        filtered_parts = [
            p for p in parts
            if not p.startswith("--")
        ]

        if len(filtered_parts) < 2:
            return []

        return [
            DockerArtifactCandidate(
                step_index=step.index,
                artifact_type="copied_file",
                source=filtered_parts[0],
                destination=filtered_parts[-1],
                source_type="local",
                reason="COPY introduces external file"
            )
        ]

    def _analyze_run(
        self,
        step: DockerStep
    ) -> list[DockerArtifactCandidate]:

        artifacts = []

        try:
            tokens = shlex.split(step.command)
        except ValueError:
            tokens = step.command.split()

        lower = [t.lower() for t in tokens]

        #
        # DOWNLOAD (curl, wget...)
        #

        for url in self._extract_urls(tokens):

            artifacts.append(

                DockerArtifactCandidate(

                    step_index=step.index,

                    artifact_type="download",

                    source=url,

                    destination=None,

                    source_type="download",

                    reason="External download detected"

                )

            )

        #
        # apt / apt-get
        #

        if "install" in lower and ("apt" in lower or "apt-get" in lower):

            for pkg in self._extract_packages(tokens, "install"):

                artifacts.append(

                    DockerArtifactCandidate(

                        step_index=step.index,

                        artifact_type="package_install",

                        source=pkg,

                        destination=None,

                        source_type="package",

                        reason="APT package installation"

                    )

                )

        #
        # apk
        #

        if "apk" in lower and "add" in lower:

            for pkg in self._extract_packages(tokens, "add"):

                artifacts.append(

                    DockerArtifactCandidate(

                        step_index=step.index,

                        artifact_type="package_install",

                        source=pkg,

                        destination=None,

                        source_type="package",

                        reason="APK package installation"

                    )

                )

        #
        # pip
        #

        if ("pip" in lower or "pip3" in lower) and "install" in lower:

            for pkg in self._extract_packages(tokens, "install"):

                artifacts.append(

                    DockerArtifactCandidate(

                        step_index=step.index,

                        artifact_type="package_install",

                        source=pkg,

                        destination=None,

                        source_type="package",

                        reason="PIP package installation"

                    )

                )

        #
        # npm
        #

        if "npm" in lower and "install" in lower:

            for pkg in self._extract_packages(tokens, "install"):

                artifacts.append(

                    DockerArtifactCandidate(

                        step_index=step.index,

                        artifact_type="package_install",

                        source=pkg,

                        destination=None,

                        source_type="package",

                        reason="NPM package installation"

                    )

                )

        #
        # gem
        #

        if "gem" in lower and "install" in lower:

            for pkg in self._extract_packages(tokens, "install"):

                artifacts.append(

                    DockerArtifactCandidate(

                        step_index=step.index,

                        artifact_type="package_install",

                        source=pkg,

                        destination=None,

                        source_type="package",

                        reason="GEM package installation"

                    )

                )

        #
        # Compilazione
        #

        compile_commands = {

            "gcc",
            "g++",
            "clang",
            "clang++",
            "make",
            "cmake",
            "go"

        }

        for token in lower:

            if token in compile_commands:

                artifacts.append(

                    DockerArtifactCandidate(

                        step_index=step.index,

                        artifact_type="compiled_binary",

                        source=token,

                        destination=None,

                        source_type="compiled",

                        reason=f"Compilation detected: {token}"

                    )

                )

        return artifacts