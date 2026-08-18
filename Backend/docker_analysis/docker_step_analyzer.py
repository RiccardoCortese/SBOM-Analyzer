from dataclasses import dataclass
from dockerfile_parse import DockerfileParser


@dataclass
class DockerStep:
    """
    Rappresenta una singola istruzione significativa del Dockerfile.
    """

    index: int

    # Tipo istruzione (RUN, COPY, FROM...)
    instruction: str

    # Contenuto dell'istruzione
    command: str

    # Dockerfile completo fino a questo punto
    dockerfile_content: str

    # Nome immagine temporanea da creare
    image_tag: str

    # Indica se può modificare il contenuto dell'immagine
    filesystem_change: bool

    # Percorso del file SBOM generato per questo step
    sbom_path: str | None = None
    
    # Risultati dell'analisi YARA per questo step
    yara_results: list | None = None


class DockerStepAnalyzer:
    """
    Analizza un Dockerfile ricostruendo l'evoluzione
    dell'immagine step per step.
    """


    def __init__(self, dockerfile_content: str):

        self.dockerfile_content = dockerfile_content

        self.steps: list[DockerStep] = []


    def parse(self) -> list[DockerStep]:
        """
        Analizza il Dockerfile e crea uno step per ogni
        istruzione rilevante.
        """

        parser = DockerfileParser()
        parser.content = self.dockerfile_content

        current_lines = []
        step_index = 0

        # Indica se stiamo raccogliendo un heredoc
        heredoc = False
        heredoc_delimiter = None
        heredoc_instruction = None
        heredoc_value = None

        for inst in parser.structure:

            instruction = inst["instruction"].upper()
            value = inst["value"].strip()

            # ========================================================
            # HEREDOC
            # ========================================================

            if heredoc:

                current_lines.append(
                    inst["content"].rstrip("\n")
                )

                # Fine heredoc
                if instruction == heredoc_delimiter:

                    heredoc = False

                    step = DockerStep(
                        index=step_index,
                        instruction=heredoc_instruction,
                        command=self._normalize_command(
                            heredoc_value
                        ),
                        dockerfile_content="\n".join(current_lines),
                        image_tag=f"sbom-analysis-step-{step_index}",
                        filesystem_change=self._changes_filesystem(
                            heredoc_instruction
                        )
                    )

                    self.steps.append(step)

                    step_index += 1

                    heredoc_delimiter = None
                    heredoc_instruction = None
                    heredoc_value = None

                continue

            # ========================================================
            # COMMENTI
            # ========================================================

            if instruction == "COMMENT":
                continue

            # ========================================================
            # INIZIO HEREDOC
            # ========================================================

            if "<<" in value:

                import re

                match = re.search(
                    r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?",
                    value
                )

                if match:

                    heredoc = True
                    heredoc_delimiter = match.group(1)
                    heredoc_instruction = instruction
                    heredoc_value = value

                    current_lines.append(
                        inst["content"].rstrip("\n")
                    )

                    continue

            # ========================================================
            # ISTRUZIONE NORMALE
            # ========================================================

            current_lines.append(
                self._format_instruction(
                    instruction,
                    value
                )
            )

            step = DockerStep(
                index=step_index,
                instruction=instruction,
                command=self._normalize_command(value),
                dockerfile_content="\n".join(current_lines),
                image_tag=f"sbom-analysis-step-{step_index}",
                filesystem_change=self._changes_filesystem(
                    instruction
                )
            )

            self.steps.append(step)

            step_index += 1

        return self.steps


    def _normalize_command(self, command: str) -> str:
        """
        Normalizza istruzioni multilinea.

        Esempio:

        RUN apt install \
            git \
            curl

        diventa:

        apt install git curl
        """

        command = command.replace("\\\n"," ")

        command = command.replace("\n"," ")

        # elimina spazi multipli
        command = " ".join(command.split())

        return command.strip()



    def _format_instruction( self, instruction: str, value: str) -> str:
        """
        Ricrea la riga Dockerfile.
        """

        return f"{instruction} {value}"



    def _changes_filesystem(self, instruction: str) -> bool:
        """
        Determina se l'istruzione modifica
        il filesystem dell'immagine.
        """

        return instruction in {

            "RUN",
            "COPY",
            "ADD"

        }



    def get_steps(self) -> list[DockerStep]:
        return self.steps