# Classe per estrarre il filesystem da un'immagine , in preparazione per l'analisi con YARA
# Prende un'immagine Docker e ricava il contenuto interno come se fosse una normale cartella
import os
from os import path
import shutil
import tempfile
import subprocess
import uuid
import tarfile
from pathlib import Path
from config import STORAGE_DIR


class DockerFilesystemExtractor:
    
    def list_files(self, root_path):
        files = []

        for root, _, filenames in os.walk(root_path):
            for filename in filenames:
                files.append(
                    os.path.relpath(
                        os.path.join(root, filename),
                        root_path
                    )
                )

        return files
    
    def get_new_files(self, old_path, new_path):
        #funzione per confrontare due cartelle e restituire i file nuovi o modificati

        old_files = set()

        for root, _, files in os.walk(old_path):
            for file in files:
                rel = os.path.relpath(
                    os.path.join(root,file),
                    old_path
                )
                old_files.add(rel)


        new_files = set()

        for root, _, files in os.walk(new_path):
            for file in files:
                rel = os.path.relpath(
                    os.path.join(root,file),
                    new_path
                )
                new_files.add(rel)


        return list(new_files - old_files)
    
    # solo per Windows, per evitare problemi con path troppo lunghi
    def long_path(self, path):
        if os.name == "nt":
            return "\\\\?\\" + os.path.abspath(path)
        return path
    
    def safe_extract(self, tar, path):
        # Estrazione sicura evitando path traversal, ossia 

        base_path = os.path.abspath(path)

        ignored = [
            "node_modules",
            ".pnpm",
            ".git",
            ".cache",
            "__pycache__",
            "dist",
            "build"
        ]

        for member in tar.getmembers():

            member_path = os.path.abspath(
                os.path.join(path, member.name)
            )

            # evita path traversal
            if os.path.commonpath([member_path, base_path]) != base_path:
                raise Exception("Unsafe tar archive")


            # ignora cartelle/file inutili
            if any(x in member.name for x in ignored):
                continue


            # ignora link simbolici e hard link
            if member.issym() or member.islnk():
                continue


            try:
                # crea prima le directory mancanti
                target_dir = os.path.dirname(member_path)

                if target_dir:
                    os.makedirs(target_dir, exist_ok=True)

                #path = self.long_path(path)
                tar.extract(member, path)

            except FileNotFoundError as e:
                print(f"[WARNING] File non estratto (path troppo lungo?): {member.name}")
                continue
            
    def extract(self, image_tag: str) -> str:

           
        docker_step_dir = os.path.join(STORAGE_DIR, "docker_step")

        os.makedirs(docker_step_dir, exist_ok=True)

        folder = tempfile.mkdtemp( prefix="d_", dir=docker_step_dir)

        container = f"extract-{uuid.uuid4().hex[:8]}"


        try:

            # crea container temporaneo
            subprocess.run(
                [
                    "docker",
                    "create",
                    "--name",
                    container,
                    image_tag
                ],
                check=True
            )


            archive = Path(folder) / "fs.tar"


            # esporta filesystem
            result = subprocess.run(
            [
                "docker",
                "export",
                container,
                "-o",
                str(archive)
            ],
            capture_output=True,
            text=True
            )

            if result.returncode != 0:
                print("===== DOCKER EXPORT FALLITO =====")
                print("STDOUT:")
                print(result.stdout)
                print("STDERR:")
                print(result.stderr)
                print("RETURN CODE:", result.returncode)

                raise Exception("docker export fallito")


            output = Path(folder) / "filesystem"

            output.mkdir(exist_ok=True)


            # estrazione tar tramite Python
            with tarfile.open(archive,"r") as tar:
                self.safe_extract(tar, output)

            return str(output)


        finally:

            # elimina container temporaneo
            subprocess.run(
                [
                    "docker",
                    "rm",
                    "-f",
                    container
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            shutil.rmtree(
                folder,
                ignore_errors=True
            )