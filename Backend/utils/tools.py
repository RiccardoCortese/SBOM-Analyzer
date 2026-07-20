import os
import platform
import zipfile
import tarfile
import requests
import stat


# =====================================================
# CONFIG VERSIONI
# =====================================================

TRIVY_VERSION = "0.72.0"
CYCLONEDX_VERSION = None   # usa latest


# =====================================================
# BIN DIRECTORY
# =====================================================

def get_bin_dir():
    """
    Restituisce la cartella bin del backend.
    """

    backend_dir = os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )

    bin_dir = os.path.join(
        backend_dir,
        "bin"
    )

    os.makedirs(
        bin_dir,
        exist_ok=True
    )

    return bin_dir



# =====================================================
# PLATFORM
# =====================================================

def get_platform():

    system = platform.system()
    arch = platform.machine().lower()


    if arch in ("amd64", "x86_64"):
        arch = "x64"

    elif arch in ("arm64", "aarch64"):
        arch = "arm64"

    else:
        raise RuntimeError(
            f"Architettura non supportata: {arch}"
        )


    return system, arch



# =====================================================
# DOWNLOAD
# =====================================================

def download_file(url: str, path: str, name: str):

    if os.path.exists(path):
        return path


    print(
        f"[BACKEND] {name} non trovato. Download..."
    )

    response = requests.get(
        url,
        timeout=60
    )

    response.raise_for_status()


    with open(path, "wb") as f:
        f.write(response.content)


    print(
        f"[BACKEND] {name} scaricato."
    )


    return path



# =====================================================
# EXTRACTION
# =====================================================

def extract_archive(
    archive_path,
    destination
):

    if archive_path.endswith(".zip"):

        with zipfile.ZipFile(
            archive_path,
            "r"
        ) as zip_ref:

            zip_ref.extractall(
                destination
            )


    elif archive_path.endswith(".tar.gz"):

        with tarfile.open(
            archive_path,
            "r:gz"
        ) as tar_ref:

            tar_ref.extractall(
                destination
            )


    else:

        raise RuntimeError(
            f"Archivio non supportato: {archive_path}"
        )



def find_executable(
    directory,
    filename
):

    for root, _, files in os.walk(directory):

        if filename in files:

            return os.path.join(
                root,
                filename
            )


    return None



def make_executable(path):

    if platform.system() != "Windows":

        os.chmod(
            path,
            os.stat(path).st_mode | stat.S_IEXEC
        )



# =====================================================
# CYCLONEDX
# =====================================================

def get_cyclonedx_filename():

    system, arch = get_platform()


    if system == "Windows" and arch == "x64":
        return "cyclonedx-win-x64.exe"


    elif system == "Linux" and arch == "x64":
        return "cyclonedx-linux-x64"


    elif system == "Darwin" and arch == "x64":
        return "cyclonedx-mac-x64"


    elif system == "Darwin" and arch == "arm64":
        return "cyclonedx-mac-arm64"


    raise RuntimeError(
        f"CycloneDX non supportato: {system}-{arch}"
    )



def get_cyclonedx_path():

    filename = get_cyclonedx_filename()


    path = os.path.join(
        get_bin_dir(),
        filename
    )


    url = (
        "https://github.com/CycloneDX/"
        "cyclonedx-cli/releases/latest/download/"
        f"{filename}"
    )


    download_file(
        url,
        path,
        "CycloneDX"
    )


    make_executable(
        path
    )


    return path



# =====================================================
# TRIVY
# =====================================================

def get_trivy_asset():

    system, arch = get_platform()


    if system == "Windows" and arch == "x64":

        return (
            f"trivy_{TRIVY_VERSION}_windows-64bit.zip",
            "trivy.exe"
        )


    elif system == "Linux" and arch == "x64":

        return (
            f"trivy_{TRIVY_VERSION}_Linux-64bit.tar.gz",
            "trivy"
        )


    elif system == "Linux" and arch == "arm64":

        return (
            f"trivy_{TRIVY_VERSION}_Linux-ARM64.tar.gz",
            "trivy"
        )


    elif system == "Darwin" and arch == "x64":

        return (
            f"trivy_{TRIVY_VERSION}_macOS-64bit.tar.gz",
            "trivy"
        )


    elif system == "Darwin" and arch == "arm64":

        return (
            f"trivy_{TRIVY_VERSION}_macOS-ARM64.tar.gz",
            "trivy"
        )


    raise RuntimeError(
        f"Trivy non supportato: {system}-{arch}"
    )



def get_trivy_path():

    asset, executable = get_trivy_asset()


    bin_dir = get_bin_dir()


    executable_path = os.path.join(
        bin_dir,
        executable
    )


    if os.path.exists(executable_path):

        return executable_path



    archive_path = os.path.join(
        bin_dir,
        asset
    )


    url = (
        "https://github.com/aquasecurity/"
        f"trivy/releases/download/v{TRIVY_VERSION}/"
        f"{asset}"
    )


    download_file(
        url,
        archive_path,
        "Trivy"
    )


    print(
        "[BACKEND] Estrazione Trivy..."
    )


    extract_archive(
        archive_path,
        bin_dir
    )


    os.remove(
        archive_path
    )


    executable_path = find_executable(
        bin_dir,
        executable
    )


    if executable_path is None:

        raise RuntimeError(
            "Trivy scaricato ma eseguibile non trovato"
        )


    make_executable(
        executable_path
    )


    return executable_path