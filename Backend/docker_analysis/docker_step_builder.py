import os
import tempfile
import subprocess
import shutil

from docker_analysis.docker_step_analyzer import DockerStep



class DockerStepBuilder:
    """
    Costruisce immagini Docker intermedie
    a partire dagli step del Dockerfile.
    """


    def __init__(self, build_context=None):
        self.build_context = build_context
        # cartella temporanea dove creare i Dockerfile
        self.temp_dir = tempfile.mkdtemp(
            prefix="docker_step_builder_"
        )



    def build(self, step: DockerStep) -> str:
        """
        Costruisce l'immagine relativa allo step.

        Ritorna il tag dell'immagine.
        """


        step_dir = os.path.join(
            self.temp_dir,
            f"step_{step.index}"
        )


        os.makedirs(
            step_dir,
            exist_ok=True
        )


        dockerfile_path = os.path.join(
            step_dir,
            "Dockerfile"
        )


        # Scrittura Dockerfile temporaneo
        with open(
            dockerfile_path,
            "w",
            encoding="utf-8"
        ) as f:

            f.write(
                step.dockerfile_content
            )


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

            print(
                "Errore build Docker:"
            )

            print(
                e.stderr
            )

            raise



    def cleanup(self):
        """
        Cancella i file temporanei.
        """

        shutil.rmtree(
            self.temp_dir,
            ignore_errors=True
        )