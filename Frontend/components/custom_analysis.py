import streamlit as st
import requests
import re

def render_custom_analysis(backend_url: str):
    # ============================================================
    # SEZIONE DI ANALISI DEI FILE CUSTOM (qualsiasi altro file di dipendenze)
    # ============================================================
    
    st.subheader("📋 File custom di dipendenze rilevati")
    custom_found = [f for f in st.session_state.found_files if f.lower() not in ["requirements.txt", "poetry.lock", "pyproject.toml"]]
    custom_file = st.selectbox(
        "Seleziona il fileda analizzare:",
        options=custom_found,
        format_func=lambda x: x.capitalize()
    )
    
    btn_col1, btn_col2 = st.columns(2)
    
    # ============================================================
    # BOTTONE PER AVVIARE L'ANALISI DEL FILE CUSTOM SELEZIONATO
    # ============================================================
    
    with btn_col1:
    
        if st.button("Avvia analisi file custom", use_container_width=True):
            
            with st.spinner("Invio richiesta al backend per generare SBOM standard..."):
                try:
                    res = requests.post(
                        f"{backend_url}/analyze-custom-file",
                        data={
                            "repo_url": st.session_state.saved_repo,
                            "branch": st.session_state.saved_branch,
                            "path_file": custom_file
                        }
                    )
                    
                    if res.status_code == 200:
                        st.session_state.analysis_results = res.json()
                        st.success("Tabella di confronto generata!")
                        st.rerun()
                        
                    else:
                        error_msg = res.json().get("detail", "Errore sconosciuto")
                        st.error(f"Analisi SBOM custom Fallita: {error_msg}")
                except Exception as e:
                    st.error(f"Errore di connessione: {str(e)}")
        # ============================================================
        # BOTTONE PER FAR PARTIRE ANALISI DEEP DEL FILE CUSTOM SELEZIONATO (con generazione di grafi e SBOM)
        # ============================================================
        
        with btn_col2:
            if st.session_state.analysis_results is not None:
                if st.button("Avvia analisi approfondita (Deep)", use_container_width=True):
                    
                    with st.spinner("Invio richiesta al backend per generare SBOM approfondito..."):
                        try:
                            res = requests.post(
                                f"{backend_url}/analyze-dependencies-sbom",
                                data={
                                    "repo_url": st.session_state.saved_repo,
                                    "branch": st.session_state.saved_branch,
                                    "path_file": custom_file
                                }
                            )
                            
                            if res.status_code == 200:
                                st.session_state.deep_sbom_results = res.json()
                                st.success("Analisi approfondita completata!")
                                st.rerun()
                                
                            else:
                                error_msg = res.json().get("detail", "Errore sconosciuto")
                                st.error(f"Analisi approfondita Fallita: {error_msg}")
                        except Exception as e:
                            st.error(f"Errore di connessione: {str(e)}")
        
    
    st.markdown("---")

    # DIPENDENZE DEL FILE CUSTOM ANALIZZATO (se esiste un risultato)
    if st.session_state.analysis_results is not None:
        
        result = st.session_state.analysis_results
        dependencies = result.get("result", [])
        git_repos = [item["url"] for item in dependencies if item.get("url") and "github.com" in item["url"]]
        component_type = result.get("component_type", None)
        
        # ============================================================
        # TABELLONE DINAMICO DI CONFRONTO (con possibilità di download dei singoli SBOM riga per riga)
        # ============================================================    
        st.markdown("### 📦 Elenco Dipendenze Rilevate nel File Custom")
        with st.container(height=1000):
            if dependencies:
                
                all_columns = {
                    "type": "Tipo",
                    "name": "Componente",
                    "component_type": "Tipo Componente",
                    "url": "Sorgente / PURL",
                    "present_in_requirements": "In Requirements",
                    "present_in_poetry": "In Poetry"
                }

                # Filtriamo le colonne in base al valore ricevuto nel primo elemento (se esiste)
                # Se il primo elemento ha "N/A" per una colonna, la escludiamo dal rendering
                first_item = dependencies[0] if dependencies else {}
                visible_keys = [
                    k for k in all_columns.keys() 
                    if k not in ["present_in_requirements", "present_in_poetry"] 
                    or first_item.get(k) != "N/A"
                ]

                # Calcoliamo i pesi (width) in base a quante colonne stiamo mostrando
                cols = st.columns([1, 2, 1.5, 3] + [1.5] * (len(visible_keys) - 4) + [1.5])
                headers = [all_columns[k] for k in visible_keys] + ["SBOM"]

                for i, h in enumerate(headers):
                    cols[i].markdown(f"**{h}**")
                st.markdown("---")

                # Rendering righe
                for idx, item in enumerate(dependencies):
                    row_cols = st.columns([1, 2, 1.5, 3] + [1.5] * (len(visible_keys) - 4) + [1.5])
                    
                    c_url = item.get("url", "")
                    c_tipo = item.get("type", "")
                    
                    for i, key in enumerate(visible_keys):
                        row_cols[i].write(item.get(key, "-"))
                    
                    # Colonna SBOM
                    with row_cols[-1]:
                        
                        # Creazione di un nome pulito per il file SBOM da scaricare, basato su URL e tipo, con sostituzione dei caratteri non alfanumerici
                        url_clean = re.sub(r'[^a-zA-Z0-9]', '-', c_url.replace("https://", "").replace("http://", ""))
                        url_clean = re.sub(r'-+', '-', url_clean).strip('-').lower()
                        c_tipo_clean = c_tipo.lower()

                        deep_results = st.session_state.get("deep_sbom_results") or {}
                        available_sboms = deep_results.get("sboms", {})

                        # Cerchiamo se il file contiene ALMENO le parti fondamentali: 
                        # il tipo e una parte significativa dell'URL (se l'URL è lungo)
                        def is_match(file_key, tipo, url_part):
                            file_key = file_key.lower()
                            # Se è un file tipo apt/pip, il nome è spesso breve
                            if tipo in ['apt', 'pip']:
                                return tipo in file_key and url_part[:10] in file_key
                            # Se è git/zip/altro, cerchiamo il tipo e il nome della repo
                            return tipo in file_key and url_part in file_key

                        matching_key = next((k for k in available_sboms.keys() if is_match(k, c_tipo_clean, url_clean)), None)
                        

                        if matching_key:
                            st.download_button(
                                label="⬇️ SBOM",
                                data=available_sboms[matching_key],
                                file_name=matching_key, 
                                mime="application/json",
                                key=f"dl_row_{idx}",
                                use_container_width=True
                            )
                        else:
                            st.button(
                                label="🚫 Non Disp.", 
                                key=f"disabled_row_{idx}", 
                                disabled=True, 
                                use_container_width=True
                            )
        