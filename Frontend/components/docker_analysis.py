import streamlit as st
import requests
import json
import pandas as pd

def render_docker_section(backend_url: str):
    st.subheader("Sezione di Analisi Immagine Docker")
    
    docker_choice = st.session_state.get("config_docker_choice", "Genera SBOM Docker")
    docker_image_tag = st.session_state.get("config_docker_image_tag", "paperlessngx/paperless-ngx:dev")
    vuln_type = st.session_state.get("config_vuln_type", "os,library")
    docker_file = st.session_state.get("config_docker_uploader", None)
    if docker_choice == "Genera SBOM Docker":
        
        if st.button("Avvia Generazione Pipeline & Confronto Docker", use_container_width=True):
        
            with st.spinner("Compilazione immagine in corso su GitHub Actions e analisi Trivy..."):
        
                try:
        
                    res_docker = requests.post(
                        f"{backend_url}/generate-docker-sbom",
                        params={
                            "repo_url": st.session_state.saved_repo,
                            "branch": st.session_state.saved_branch,
                            "docker_target": docker_image_tag,
                            "vuln_type": vuln_type
                        }
                    )
        
                    if res_docker.status_code == 200:
        
                        response_data = res_docker.json()
        
                        if "graphs" in response_data:
        
                            st.session_state["docker_results"]["graphs"] = response_data["graphs"]
                        
                        if "hierarchy_with_weights" in response_data:
        
                            st.session_state["docker_results"]["hierarchy_with_weights"] = response_data["hierarchy_with_weights"]
                        
                        if "docker_report" in response_data:
        
                            # Se esiste già un'analisi del codice base, iniettiamo i dati Docker al suo interno
        
                            if st.session_state.analysis_results is not None:
        
                                st.session_state.analysis_results["docker_report"] = response_data["docker_report"]
                                st.session_state.analysis_results["raw_docker_sbom"] = response_data.get("raw_docker_sbom", "")
        
                            else:
        
                                # Fallback: se l'utente non ha premuto il Bottone 1, creiamo la struttura minima
                                st.session_state.analysis_results = {
                                    "result": [],
                                    "docker_report": response_data["docker_report"],
                                    "raw_docker_sbom": response_data.get("raw_docker_sbom", "")
                                }
                        
                        st.session_state.docker_analyzed = True
                        st.success("SBOM Docker generato con successo! Statistiche aggiornate sotto.")
                        st.rerun()
        
                    else:
                        st.error(f"Errore generazione Docker: {res_docker.text}")
        
                except Exception as e:
                    st.error(f"Errore di connessione: {str(e)}")

    elif docker_choice == "Carica SBOM Docker esistente (JSON)":
        
        if docker_file and not st.session_state.docker_analyzed:
        
            if st.button("📊 Applica File Docker Caricato al Confronto", use_container_width=True):
        
                # Se si carica manualmente lo SBOM, ci assicuriamo che esista un contenitore in session_state
                if st.session_state.analysis_results is None:
        
                    st.session_state.analysis_results = {"result": [], "docker_report": {}}
                
                try:
                    # Parsing del file caricato dall'utente e inserimento nello stato
                    uploaded_content = json.loads(docker_file.getvalue().decode("utf-8"))
                    st.session_state.docker_analyzed = True
                    st.rerun()
        
                except Exception as e:
                    st.error(f"Errore nel parsing del file JSON caricato: {str(e)}")

    # --- RE-ESTRAZIONE DATI AGGIORNATI DA SESSION STATE PER IL RENDERING ---
    current_results = st.session_state.analysis_results if st.session_state.analysis_results else {}
    current_docker_report = current_results.get("docker_report", {})

    # Rendering dei risultati dinamici basati sullo stato aggiornato
    if st.session_state.docker_analyzed and current_docker_report and current_docker_report.get("total_docker_packages", 0) > 0:
        
        st.markdown("#### 📊 Statistiche e Deviazioni dell'Immagine Docker")
        
        kpi1, kpi2, kpi3, kpi4, kpi5, kpi6 = st.columns(6)
        kpi1.metric("Totale Pacchetti nel Docker", current_docker_report.get("total_docker_packages", 0))
        kpi2.metric("Totale Pacchetti Unici nel Docker", current_docker_report.get("total_unique_docker_packages", 0))
        kpi3.metric("✅ In Comune con i Sorgenti", current_docker_report.get("packages_in_common_count", 0))
        kpi4.metric("⚠️ Esclusivi Docker", current_docker_report.get("packages_only_in_docker_count", 0))
        kpi5.metric("❗ Versioni Differenti (Tra Docker e Sorgenti)", current_docker_report.get("packages_with_version_mismatches_count", 0))
        kpi6.metric("❌ Mancanti nel Docker", current_docker_report.get("packages_missing_in_docker_count", 0))

        raw_docker_sbom = current_results.get("raw_docker_sbom", "")

        # Colonne per i bottoni di download
        dl_col1, dl_col2 = st.columns(2)
        
        with dl_col1:
            st.download_button(
                label="⬇️ Scarica Report degli elementi SOLO nel Docker",
                data=json.dumps(current_docker_report, indent=2),
                file_name="docker_cross_reference_report.json",
                mime="application/json",
                use_container_width=True
            )
        
        with dl_col2:
        
            if raw_docker_sbom:
        
                st.download_button(
                    label="⬇️ Scarica SBOM Docker Completo",
                    data=raw_docker_sbom,
                    file_name="cyclonedx-SBOM.json",
                    mime="application/json",
                    use_container_width=True
                )
        
            else:
        
                st.button(
                    label="🚫 SBOM Docker originale non disponibile",
                    disabled=True,
                    use_container_width=True
                )
        

        with st.expander(f"🟢 Pacchetti comuni tra Docker e Sorgente ({current_docker_report.get('packages_in_common_count', 0)})"):
            if current_docker_report.get("in_common"):
                
                data = []
                for item in current_docker_report["in_common"]:
                    sources = [f["source"] for f in item.get("source_files", [])]
                    data.append({
                        "Componente": item["name"],
                        "Versione": item["version"],
                        "PURL": item.get("purl", "-"),
                        "File Sorgente (oltre a immagine docker)": ", ".join(sources)
                    })
                st.dataframe(pd.DataFrame(data), use_container_width=True)
            else:
                st.info("Nessuna corrispondenza trovata.")
        
        
        with st.expander(f"🔴 Pacchetti solo dentro l'Immagine Docker ({current_docker_report.get('packages_only_in_docker_count', 0)})"):
            st. info("Questa sezione mostra i pacchetti presenti solo nell'immagine Docker.")
            
            if current_docker_report.get("only_in_docker"):
                data = []
                for item in current_docker_report["only_in_docker"]:
                    data.append({
                        "Componente": item["name"],
                        "Versione": item["version"],
                        "PURL": item.get("purl", "-")
                    })
                st.dataframe(pd.DataFrame(data), use_container_width=True)
            else:
        
                st.info("Nessun pacchetto extra rilevato.")
        
        with st.expander(f"⚠️ Pacchetti con Versioni Differenti ({len(current_docker_report.get('version_mismatches', []))})"):
            mismatches = current_docker_report.get("version_mismatches", [])
            if mismatches:
                df_mismatch = pd.DataFrame([
                    {
                        "Componente": m["docker"]["name"],
                        "Versione Docker": m["docker"].get("version", "-"),
                        "Versione Sorgente": m.get("code_version", "-"),
                        "File Sorgente": ", ".join([f["source"] for f in m.get("source_files", [])])
                    } for m in mismatches
                ])
                st.dataframe(df_mismatch, use_container_width=True)
            else:
                st.info("Nessuna discrepanza di versione rilevata.")
            
        with st.expander(f"❌ Pacchetti Mancanti nel Docker SBOM ({len(current_docker_report.get('missing_in_docker', []))})"):
            st. info("Questa sezione mostra le dipendenze che sono presenti nei sorgenti della repository ma non sono state rilevate nell'immagine Docker.")
            missing_in_docker = current_docker_report.get("missing_in_docker", [])
            
            if missing_in_docker:
                # Creazione di un DataFrame per visualizzare le dipendenze mancanti in modo tabellare
                df_missing = pd.DataFrame([
                    {
                        "Componente": m.get("name", "-"),
                        "Versione Sorgente": m.get("version", "-"),
                        "PURL": m.get("purl", "-"),
                        "File Sorgente (oltre a immagine docker)": ", ".join(m.get("files", []))
                    } for m in missing_in_docker
                ])
                st.dataframe(df_missing, use_container_width=True)
        
            else:
                st.info("Nessuna dipendenza mancante rilevata nel Docker SBOM.")
    else:
        
        if docker_choice == "Genera SBOM Docker":
        
            st.info("💡 Clicca sul pulsante sopra per avviare la compilazione remota dell'immagine Docker e analizzarla.")
        
        else:
        
            st.info("💡 Carica lo SBOM Docker al Punto 1 e clicca su 'Applica File Docker Caricato al Confronto' per vedere l'analisi.")