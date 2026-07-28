import os
import tempfile
import subprocess
import shutil

from docker_analysis.docker_step_analyzer import DockerStep
from config import STORAGE_DIR


class DockerStepBuilder:
    """
    Costruisce immagini Docker intermedie
    a partire dagli step del Dockerfile.
    """


    def __init__(self, build_context=None):
        self.build_context = build_context
        
        # Normalizza i file di script nella build context per evitare problemi di fine linea
        if self.build_context:
            self.normalize_line_endings(
            self.build_context
        )
        
        # Cartella temporanea dove creare i Dockerfile
        docker_step_dir = os.path.join(STORAGE_DIR,"docker_step")

        os.makedirs(docker_step_dir,exist_ok=True)

        self.temp_dir = tempfile.mkdtemp(prefix="docker_step_builder_",dir=docker_step_dir)


    # normalizzazione dei file di script (bash, sh, py) per evitare problemi di fine linea
    def normalize_line_endings(self, path):
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith((".py", ".sh", ".bash")):
                    file_path = os.path.join(root, file)

                    try:
                        with open(file_path, "rb") as f:
                            content = f.read()

                        content = content.replace(
                            b"\r\n",
                            b"\n"
                        )

                        with open(file_path, "wb") as f:
                            f.write(content)

                    except Exception:
                        pass

    def build(self, step: DockerStep) -> str:
        """
        Costruisce l'immagine relativa allo step.

        Ritorna il tag dell'immagine.
        """


        step_dir = os.path.join( self.temp_dir, f"step_{step.index}")

        os.makedirs( step_dir, exist_ok=True)

        dockerfile_path = os.path.join( step_dir, "Dockerfile")

        # Scrittura Dockerfile temporaneo
        with open( dockerfile_path, "w", encoding="utf-8", newline="\n") as f:
            f.write( step.dockerfile_content.replace("\r\n", "\n") )


        image_tag = step.image_tag

        command = [
            "docker",
            "build",
            "-t",
            image_tag,
            "-f",
            dockerfile_path,
            self.build_context if self.build_context else "."
        ]

        try:

            result = subprocess.run(
                command,
                capture_output=True,
                text=True
            )

            print("===== DOCKER STDOUT =====")
            print(result.stdout)

            print("===== DOCKER STDERR =====")
            print(result.stderr)


            if result.returncode != 0:
                raise RuntimeError(
                    f"Docker build fallito per step {step.index}:\n{result.stderr}"
                )


            print(
                f"[DOCKER BUILD] Step {step.index} completato"
            )


            return image_tag


        except subprocess.CalledProcessError as e:

            print("Errore build Docker:")

            print(e.stderr)

            raise



    def cleanup(self):
        """
        Cancella i file temporanei.
        """

        # Pulizia cartella temporanea
        shutil.rmtree( self.temp_dir, ignore_errors=True)
        
        # Pulizia immagini intermedie
        subprocess.run(
        [
            "docker",
            "image",
            "prune",
            "-f"
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )