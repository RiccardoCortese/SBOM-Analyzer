import streamlit as st
import requests
import json

def render_merge_sboms(backend_url: str):

    st.subheader("Calcolo Grafi e Merge Artefatti")
    col1, col2 = st.columns([1, 1])

    with col1:
        st.info("Clicca qui per unire gli artefatti")
        if st.button("Unisci Artefatti SBOM", use_container_width=True):
            with st.spinner("Unione artefatti in corso..."):
                try:
                    res_merge = requests.get(f"{backend_url}/merge-artifacts")
                    if res_merge.status_code == 200:
                        merge_data = res_merge.json()
                        st.session_state.merged_results = merge_data
                        st.success("Artefatti uniti con successo!")
                        st.rerun()
                    else:
                        error_msg = res_merge.json().get("detail", "Errore sconosciuto")
                        st.error(f"Unione Artefatti Fallita: {error_msg}")
                except Exception as e:
                    st.error(f"Errore di connessione: {str(e)}")

    with col2:
        st.info("Clicca qui per generare i grafi delle dipendenze")
        if st.button("Genera Grafi Dipendenze", use_container_width=True):
            with st.spinner("Generazione grafi in corso..."):
                try:
                    res_graphs = requests.get(f"{backend_url}/generate-graphs")
                    if res_graphs.status_code == 200:
                        graph_data = res_graphs.json()
                        st.session_state.setdefault("deep_sbom_results", {}).update(graph_data)
                        st.success("Grafi generati con successo!")
                        st.rerun()
                    else:
                        error_msg = res_graphs.json().get("detail", "Errore sconosciuto")
                        st.error(f"Generazione Grafi Fallita: {error_msg}")
                except Exception as e:
                    st.error(f"Errore di connessione: {str(e)}")

    if st.session_state.merged_results is not None:
        st.subheader("📦 Risultati Unione Artefatti SBOM")
        st.download_button(
            label="Scarica SBOM Unificato",
            data=json.dumps(st.session_state.merged_results["data"]),
            file_name="final_merged_sbom.json",
            mime="application/json"
        )
        with st.container(height=300):
            st.json(st.session_state.merged_results["data"])