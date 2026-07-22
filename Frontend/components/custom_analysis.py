import streamlit as st
import requests
import json
import re

def render_custom_analysis(backend_url: str):
    # ============================================================
    # SEZIONE DI ANALISI DEI FILE CUSTOM (qualsiasi altro file di dipendenze)
    # ============================================================
    
    st.subheader("Immagini docker rilevate nel dockerfile")
    
    for i, image in enumerate(st.session_state.images):
        
        def extract_image(from_line: str):
            # rimuove "FROM"
            line = from_line.strip()
            line = re.sub(r"^FROM\s+", "", line, flags=re.IGNORECASE)

            # rimuove flags tipo --platform=...
            line = re.sub(r"--\S+\s+", "", line)

            # rimuove AS stage
            line = re.split(r"\s+AS\s+", line, flags=re.IGNORECASE)[0]

            return line.strip()

        clear_image = extract_image(image)
        
        docker_image_tag_custom = st.text_input(
            "Tag Immagine / Nome Dockerfile custom:",
            value= clear_image,
            key=f"docker_image_tag_custom_{i}"
        )
        
        # Tipo di vulnerabilità da scansionare con Trivy
        vuln_type_custom = st.selectbox(
            "Seleziona cosa scansionare nell'immagine Docker:",
            
            options=["os,library", "os", "library"],
            
            format_func=lambda x: {
                "os,library": "Tutto (Sia OS che Librerie di linguaggio)",
                "os": "Solo pacchetti del Sistema Operativo",
                "library": "Solo librerie dell'applicazione"
            }[x],
            
            index=0,  # Default su tutto
            key=f"vuln_type_custom_{i}"
        )
    
    
        # ============================================================
        # BOTTONE PER AVVIARE L'ANALISI DEL FILE CUSTOM SELEZIONATO
        # ============================================================
        
        
        if st.button("Avvia analisi file custom", use_container_width=True, key=f"analyze_custom_{i}"):
            
            with st.spinner("Invio richiesta al backend per generare SBOM standard..."):
                try:
                    res = requests.post(
                        f"{backend_url}/analyze-custom-file",
                        data={
                            "docker_image_tag_custom": docker_image_tag_custom,
                            "vuln_type_custom": vuln_type_custom
                        }
                    )
                    
                    if res.status_code == 200:
                        st.session_state.analysis_results[i]= res.json()
                        st.success("Analisi immagine docker custom completata!")
                        st.rerun()
                        
                    else:
                        error_msg = res.json().get("detail", "Errore sconosciuto")
                        st.error(f"Analisi SBOM custom Fallita: {error_msg}")
                except Exception as e:
                    st.error(f"Errore di connessione: {str(e)}")
                    
        if st.session_state.analysis_results is not None and i in st.session_state.analysis_results:
            item = st.session_state.analysis_results[i]["data"]

            st.subheader(f"📦 Risultato per {item["filename"]}")

            with st.container(height=300, key=f"custom_result_{i}"):
                st.json(item["content"])

            col_btn1, col_btn2 = st.columns([1, 1])

            with col_btn1:
                st.link_button("🔗 Vedi Log Action", item["github_run_url"], use_container_width=True, key=f"link_custom_{i}")

            with col_btn2:
                json_str = json.dumps(item["content"], indent=4)

                st.download_button(
                    label="⬇️ Scarica SBOM JSON",
                    data=json_str,
                    file_name=f"sbom_{item["filename"].replace('.', '_')}.json",
                    mime="application/json",
                    use_container_width=True,
                    key=f"download_custom_{i}"
                )
        st.markdown("---")
