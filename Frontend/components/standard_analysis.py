import streamlit as st
import requests
import json
from components.docker_parser_component import render_docker_sbom_analysis

def render_standard_analysis(backend_url: str):
    # Recuperiamo le analisi dal session_state (se le hai salvate lì dal backend)
    
    st.subheader("📦 File di dipendenze rilevati")
    
    # Visualizzazione dinamica
    for file_name in st.session_state.found_files:
        st.markdown(f"📄 **{file_name}**")

    if "images" in st.session_state and st.session_state.images:
        st.subheader("Immagini Docker rilevate")
        for img in st.session_state.images:
            st.code(f"FROM {img}", language="docker")
    else:
        st.info("Nessuna immagine Docker rilevata.")
    st.markdown("---")
    
    if st.session_state.get("analysis_done", False):
        st.subheader("📊 Risultati Analisi SBOM Docker")
        render_docker_sbom_analysis(
            st.session_state.steps,
            st.session_state.diffs,
            st.session_state.artifacts,
            st.session_state.yara_results
        )
    
    st.markdown("---")
    
    # ===========================================================
    # SEZIONE DI ANALISI DEI FILE STANDARD (requirements.txt, poetry.lock, pyproject.toml)
    # ===========================================================
    
    st.subheader("📋 File \"standard\" di dipendenze rilevati")
    
    format_type = st.selectbox(
        "Seleziona il formato da cui generare SBOM tramite la pipeline:",
        options=st.session_state.found_files + ["Entrambi"],
        format_func=lambda x: x.capitalize()
    )
    
    st.session_state.saved_format = format_type
    
    st.info(" Verrà inviato questo target alla pipeline remota di GitHub Actions per generare lo SBOM standard.")

    if st.button("Avvia analisi SBOM standard"):
        st.session_state.analysis_results_advanced = True
        
        with st.spinner("Invio richiesta al backend per generare SBOM standard..."):
            try:
                res = requests.post(
                    f"{backend_url}/analyze-standard-file",
                    data={
                        "format": format_type,
                        "repo_url": st.session_state.saved_repo,
                        "branch": st.session_state.saved_branch
                    }
                )
                if res.status_code == 200:
                    st.session_state.analysis_results_standard = res.json()
                    st.success("Analisi SBOM Standard completata!")
                    
                else:
                    error_msg = res.json().get("detail", "Errore sconosciuto")
                    st.error(f"Analisi SBOM Standard Fallita: {error_msg}")
            except Exception as e:
                st.error(f"Errore di connessione: {str(e)}")
    
    # ============================================================
    # SEZIONE DI VISUALIZZAZIONE DEI RISULTATI DEL FILE STANDARD
    # ============================================================
    
    if st.session_state.analysis_results_standard is not None:
        for item in st.session_state.analysis_results_standard["data"]:
            st.subheader(f"📦 Risultato per {item['file_name']}")

            with st.container(height=300):
                st.json(item["content"])

            col_btn1, col_btn2 = st.columns([1, 1])

            with col_btn1:
                st.link_button("🔗 Vedi Log Action", item["github_run_url"], use_container_width=True)

            with col_btn2:
                # preparazione del contenuto JSON per il download
                # Creiamo una stringa JSON formattata con indentazione per il download
                json_str = json.dumps(item["content"], indent=4)
                
                st.download_button(
                    label="⬇️ Scarica SBOM JSON",
                    data=json_str,
                    file_name=f"sbom_{item['file_name'].replace('.', '_')}.json",
                    mime="application/json",
                    use_container_width=True
                )

            st.divider() # Separatore grafico tra i file
            st.markdown("---")