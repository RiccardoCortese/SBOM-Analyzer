import streamlit as st
import requests

def render_config_target(backend_url: str):
    # ============================================================
    # CONFIGURAZIONE TARGET & SBOM DI BASE (Repo + SBOM Base + Docker)
    # ============================================================
    st.subheader("Configurazione Target & SBOM di Base")

    repo_url = st.text_input("GitHub Repository URL", value=st.session_state.saved_repo, placeholder="https://github.com/owner/repo")
    branch = st.text_input("Branch", value=st.session_state.saved_branch)
    st.info(" Inserisci la URL della repository GitHub e il branch da analizzare.")
    st.markdown("---")

    # ===============================================================
    # SBOM DINAMICO (analisi tramite Dockerfile)
    # ==============================================================

    dockerfile_path = st.text_input("Percorso del Dockerfile nella repo", value="Dockerfile")
    st.info(f"Il tool analizzerà il file {dockerfile_path} per scoprire le dipendenze.")

    st.markdown("---")

    # ============================================================
    # SELEZIONE INPUT DOCKER (generazione o upload SBOM esistente)
    # ============================================================
    docker_choice = st.radio(
        "Origine Analisi Immagine Docker:",
        ["Genera SBOM Docker", "Carica SBOM Docker esistente (JSON)"],
        horizontal=False
    )
        
    docker_file = None
    if docker_choice == "Carica SBOM Docker esistente (JSON)":
        # Se l'utente sceglie di caricare un file SBOM Docker, mostriamo il file uploader per caricare il file JSON
        
        docker_file = st.file_uploader("Carica lo SBOM dell'immagine Docker", type=["json"])

    elif docker_choice == "Genera SBOM Docker":
        # Se l'utente sceglie di generare lo SBOM Docker, mostriamo i campi per il tag dell'immagine e il tipo di vulnerabilità da scansionare
            
        docker_image_tag = st.text_input(
            "Tag Immagine / Nome Dockerfile custom:",
            value="paperlessngx/paperless-ngx:dev",
            placeholder="es. myrepo/myimage:latest"
        )
        
        # Tipo di vulnerabilità da scansionare con Trivy
        vuln_type = st.selectbox(
            "Seleziona cosa scansionare nell'immagine Docker:",
            
            options=["os,library", "os", "library"],
            
            format_func=lambda x: {
                "os,library": "Tutto (Sia OS che Librerie di linguaggio)",
                "os": "Solo pacchetti del Sistema Operativo",
                "library": "Solo librerie dell'applicazione"
            }[x],
            
            index=0  # Default su tutto
        )
        st.info(" Verrà inviato questo target alla pipeline remota di GitHub Actions.")


    if st.button("🔄 Invia e Avvia Discovery"):
        if not repo_url:
            st.error("Inserisci la URL della repo.")
            st.stop()
            
        st.session_state.saved_repo = repo_url
        st.session_state.saved_branch = branch
        st.session_state.docker_analyzed = False

        data_payload = {
            "action": "generate", 
            "mode": "docker",
            "dockerfile_path": dockerfile_path,
            "manual_format": st.session_state.saved_format,
            "repo_url": repo_url,
            "branch": branch
        }
        
        files_payload = {}
        
        if docker_choice == "Carica SBOM Docker esistente (JSON)" and docker_file:
            files_payload["docker_file"] = docker_file.getvalue()

        # Invio al backend
        with st.spinner("Configurazione analisi in corso..."):
            try:
                res = requests.post(f"{backend_url}/upload-sbom", data=data_payload, files=files_payload)
                if res.status_code == 200:
                    risposta = res.json()
                    st.success(f"Configurazione accettata: {risposta.get('message')}")
                
                    st.session_state.found_files = risposta.get("files", [])
                    st.session_state.steps = risposta.get("steps", [])
                    st.session_state.images = risposta.get("images", [])
                    st.session_state.diffs = risposta.get("diffs", [])
                    st.session_state.artifacts = risposta.get("artifacts", [])
                    st.session_state.yara_results = risposta.get("yara", [])
                    st.session_state.analysis_done = True
                    st.info(f"Ho trovato {len(st.session_state.found_files)} file di dipendenze.")
                    st.rerun()
                else:
                    # Se il backend fallisce, mostriamo l'errore specifico
                    error_msg = res.json().get("detail", "Errore sconosciuto")
                    st.error(f"Discovery Fallita: {error_msg}")
                    st.warning("Suggerimento: Verifica che il percorso del Dockerfile sia corretto o passa alla modalità Manuale.")
            except Exception as e:
                st.error(f"Errore di connessione: {str(e)}")