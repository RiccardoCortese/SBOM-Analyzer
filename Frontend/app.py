import streamlit as st
import requests
import pandas as pd
import json

st.set_page_config(
    page_title="TLSAssistant SBOM Analyzer",
    layout="wide"
)

st.title("TLSAssistant - SBOM & Dependency Analyzer")

BACKEND_URL = "http://127.0.0.1:8000"

# ============================================================
# INSERIMENTO REPOSITORY DI INPUT 
# ============================================================
st.subheader("1. Configurazione Target")
repo_url = st.text_input(
    "GitHub Repository URL da analizzare", 
    placeholder="https://github.com/owner/repo"
)

branch = st.text_input(
    "Branch della Repository", 
    value="main"
)

st.markdown("---")

# ============================================================
# SCELTA SBOM STATICO (SÌ / NO) o UPLOAD FILE MANUALI
# ============================================================
st.subheader("2. Opzioni di Analisi")

# Inizializzazione parametri dinamici di default
format_type = "entrambi"
requirements_file = None
poetry_file = None

# Scelta della modalità operativa
sbom_generation_choice = st.radio(
    "Vuoi generare lo SBOM statico (requirements.txt e poetry.lock) tramite GitHub Actions o fornire direttamente i file di dipendenze?",
    ["Genera SBOM Statico", "Fornisci File Dipendenze"],
    index=0,
    horizontal=True
)

if sbom_generation_choice == "Genera SBOM Statico":
    format_type = st.radio(
        "Seleziona cosa scansionare per lo SBOM statico:",
        ["Requirements", "Poetry", "Entrambi"],
        index=2,
        horizontal=True
    ).lower()
else:
    st.markdown("### 📤 Caricamento File di Dipendenze Locali")
    
    col1, col2 = st.columns(2)
    
    with col1:
        requirements_file = st.file_uploader(
            "Carica SBOM per Requirements",
            type=["txt", "json"],
            key="req_uploader"
        )
        
    with col2:
        poetry_file = st.file_uploader(
            "Carica SBOM per Poetry",
            type=["lock", "json"],
            key="poetry_uploader"
        )
    

st.markdown("---")


st.subheader("3. File dipendenze dinamiche")
path_dipendenze = st.text_input(
    "Specifica il percorso o il nome del file di dipendenze all'interno della repo:",
    value="dependencies.json",
)

path_dipendenze = path_dipendenze.strip() # Rimuove spazi bianchi superflui

# ============================================================
# AVVIO PROCESSO DI ANALISI
# ============================================================
if st.button("Avvia Analisi"):
    if not repo_url:
        st.error("Inserisci l'URL di una repository GitHub prima di procedere.")
        st.stop()

    with st.spinner("Comunicazione con il Backend in corso..."):
        try:
            response = None

            # ----------------------------------------------------
            # STRADA A: GENERAZIONE SBOM STATICO (GITHUB ACTIONS)
            # ----------------------------------------------------
            if sbom_generation_choice == "Genera SBOM Statico":
                response = requests.post(
                    f"{BACKEND_URL}/analyze-static",
                    params={
                        "repo_url": repo_url,
                        "branch": branch,
                        "format_type": format_type
                    }
                )

            # ----------------------------------------------------
            # STRADA B: PARSING DEI FILE FORNITI MANUALMENTE
            # ----------------------------------------------------
            else:
                # Costruiamo il dizionario multipart dei file solo se l'utente li ha caricati
                upload_files = {}
                
                if requirements_file is not None:
                    upload_files["requirements_file"] = (
                        requirements_file.name,
                        requirements_file.getvalue(),
                        "application/octet-stream"
                    )
                
                if poetry_file is not None:
                    upload_files["poetry_file"] = (
                        poetry_file.name,
                        poetry_file.getvalue(),
                        "application/octet-stream"
                    )

                if not upload_files:
                    st.error("Carica almeno uno dei due file (Requirements o Poetry) prima di avviare l'analisi manuale.")
                    st.stop()

                response = requests.post(
                    f"{BACKEND_URL}/analyze-files", 
                    params={
                        "repo_url": repo_url,
                        "branch": branch
                    },
                    files=upload_files
                )

            # Controllo risposta HTTP dal backend
            if response is None or response.status_code != 200:
                st.error(f"Errore restituito dal server: {response.text if response else 'Nessuna risposta'}")
                st.stop()

            result = response.json()
            
            if result.get("status") == "error":
                st.error(result.get("message", "Errore durante l'elaborazione del backend."))
                st.stop()

            st.success("Analisi completata con successo!")

            # ====================================================
            # VISUALIZZAZIONE RISULTATI 
            # ====================================================
            st.subheader("📊 Risultati dell'Analisi")
            
            dependencies = result.get("dependencies", [])
            git_repos = result.get("detected_git_repos", [])
            comparison_report = result.get("comparison_matrix", None)

            # Costruzione dei Tab dinamici basati sul tipo di risposta ottenuta
            tab_labels = ["📦 Componenti Rilevati" + f" ({len(dependencies)})", "🔗 Link GitHub Sorgenti"]
            if comparison_report:
                tab_labels.append("🔍 Matrice di Confronto (Pipeline)")
            tab_labels.append("📄 JSON Grezzo Export")

            tabs = st.tabs(tab_labels)

            # --- TAB 1: ELENCO COMPONENTI ---
            with tabs[0]:
                if dependencies:
                    df = pd.DataFrame(dependencies)
                    cols_desiderate = ["type", "component_type", "name", "version", "purl", "language", "github_repo"]
                    available_cols = [c for c in cols_desiderate if c in df.columns]
                    df = df[available_cols]
                    
                    st.dataframe(df, use_container_width=True)
                    st.download_button(
                        "⬇️ Scarica Elenco Componenti (JSON)",
                        json.dumps(dependencies, indent=2),
                        "dependencies_extracted.json",
                        "application/json"
                    )
                else:
                    st.info("Nessuna lista componenti strutturata disponibile o estratta da questa esecuzione.")

            # --- TAB 2: REPOSITORY SORGENTI IDENTIFICATE ---
            with tabs[1]:
                if git_repos:
                    st.markdown("### Repository esterne associate alle dipendenze:")
                    for r in git_repos:
                        st.markdown(f"- 🐙 [{r}]({r})")
                else:
                    st.info("Nessuna repository GitHub mappata come dipendenza diretta.")

            # --- TAB 3 (OPZIONALE): MATRICE DI CONFRONTO ---
            current_tab_idx = 2
            if comparison_report:
                with tabs[2]:
                    st.markdown("### Output di Divergenza Generato dagli Script")
                    if result.get("github_run_url"):
                        st.markdown(f"🌐 [Link alla Run di GitHub Actions]({result.get('github_run_url')})")
                    st.text_area("Log di Confronto:", value=comparison_report, height=400)
                current_tab_idx = 3

            # --- TAB FINALE: EXPORT COMPLETO DELLO SBOM ---
            with tabs[current_tab_idx]:
                st.code(json.dumps(result, indent=2), language="json")
                st.download_button(
                    "⬇️ Scarica Output SBOM Finale",
                    json.dumps(result, indent=2),
                    "sbom_full_output.json",
                    "application/json"
                )

        except requests.exceptions.ConnectionError:
            st.error("Errore di connessione: il Backend non è raggiungibile sulla porta 8000.")