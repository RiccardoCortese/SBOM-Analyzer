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


        # Istruzioni che vogliamo tracciare
        tracked_instructions = {
            "FROM",
            "RUN",
            "COPY",
            "ADD",
            "ARG",
            "ENV",
            "WORKDIR",
            "USER",
            "ENTRYPOINT",
            "CMD",
            "LABEL",
            "EXPOSE",
            "VOLUME",
            "HEALTHCHECK"
        }


        for inst in parser.structure:

            instruction = inst["instruction"].upper()
            value = inst["value"].strip()


            # ignora commenti del parser
            if instruction == "COMMENT":
                continue


            # Ignora istruzioni non interessanti
            #if instruction not in tracked_instructions:
            #    continue


            # Ricostruzione Dockerfile progressivo
            current_lines.append(
                self._format_instruction(
                    instruction,
                    value
                )
            )


            command = self._normalize_command(value)


            step = DockerStep(

                index=step_index,

                instruction=instruction,

                command=command,

                dockerfile_content="\n".join(
                    current_lines
                ),

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



    def _format_instruction(
        self,
        instruction: str,
        value: str
    ) -> str:
        """
        Ricrea la riga Dockerfile.
        """

        return f"{instruction} {value}"



    def _changes_filesystem(
        self,
        instruction: str
    ) -> bool:
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