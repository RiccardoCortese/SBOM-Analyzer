# Server per ricercare possibili artifacts malevoli in un'immagine Docker

from dataclasses import dataclass
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

        #
        # Determina il tipo di sorgente
        #
        source_type = "local"
        reason = "COPY introduce file esterno"

        if "--from=" in command:
            source_type = "stage"
            reason = "COPY da uno stage precedente"

        #
        # ======================================================
        # COPY JSON
        #
        # COPY ["a", "b", "/dest"]
        # COPY --chown=... ["a", "b", "/dest"]
        # COPY --from=builder ["a", "/dest"]
        # ======================================================
        #
        start = command.find("[")
        end = command.rfind("]")

        if start != -1 and end != -1:

            try:

                args = json.loads(command[start:end + 1])

                destination = args[-1]

                for src in args[:-1]:

                    artifacts.append(
                        DockerArtifactCandidate(
                            step_index=step.index,
                            artifact_type="copied_file",
                            source=src,
                            destination=destination,
                            source_type=source_type,
                            reason=reason
                        )
                    )

                return artifacts

            except json.JSONDecodeError:
                pass

        #
        # ======================================================
        # COPY classico
        #
        # COPY src dest
        # COPY src1 src2 dest
        # COPY --chown=... src dest
        # COPY --from=builder src dest
        # ======================================================
        #

        parts = shlex.split(command)

        # rimuove tutte le opzioni (--chown, --from, ...)
        parts = [
            p for p in parts
            if not p.startswith("--")
        ]

        if len(parts) < 2:
            return []

        destination = parts[-1]

        sources = parts[:-1]

        for src in sources:

            artifacts.append(
                DockerArtifactCandidate(
                    step_index=step.index,
                    artifact_type="copied_file",
                    source=src,
                    destination=destination,
                    source_type=source_type,
                    reason=reason
                )
            )

        return artifacts

    def _analyze_run( self, step: DockerStep) -> list[DockerArtifactCandidate]:

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
                    reason="Download di file esterno"
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
                        reason="Installazione pacchetto APT"
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
                        reason="Installazione pacchetto APK"
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
                        reason="Installazione pacchetto PIP"
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
                        reason="Installazione pacchetto NPM"
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
                        reason="Installazione pacchetto GEM"
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
                        reason=f"Trovata compilazione: {token}"
                    )
                )

        return artifacts