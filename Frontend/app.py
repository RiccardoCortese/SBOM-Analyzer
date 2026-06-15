import streamlit as st
import requests
import pandas as pd

st.set_page_config(page_title="TLSAssistant Dependency Analyzer", layout="wide")
st.title("Analizzatore Dipendenze TLSAssistant")
st.markdown("Carica il file strutturato `dependency.json` per mappare le componenti installate ed eseguire audit di sicurezza.")

BACKEND_URL = "http://127.0.0.1:8000/analyze"

uploaded_file = st.file_uploader("Trascina qui il tuo file dependency.json", type=["json"])

if uploaded_file is not None:
    if st.button("Avvia Estrazione e Scansione"):
        with st.spinner("Il Backend sta elaborando il file..."):
            
            files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/json")}
            
            try:
                response = requests.post(BACKEND_URL, files=files)
                
                if response.status_code == 200:
                    result = response.json()
                    st.success(f"Analisi completata con successo! Rilevate {result.get('count')} entità.")
                    
                    # Tabella Riassuntiva Web
                    st.subheader("Tabella Componenti Rilevati")
                    deps_data = result.get("dependencies", [])
                    if deps_data:
                        df = pd.DataFrame(deps_data)
                        # Riordiniamo e rinominiamo le colonne per massima chiarezza nella tesi
                        df = df[["type", "name", "version", "purl", "language", "github_repo"]]
                        df.columns = ["Tipo Installazione", "Nome / Risorsa", "Versione", "PURL Generato", "Linguaggio/Ambiente", "Repository GitHub"]
                        st.dataframe(df, use_container_width=True)
                    
                    # Elenco Repository GitHub Trovate
                    st.subheader("Repository GitHub Identificate (Sorgenti Esterne)")
                    git_repos = result.get("detected_git_repos", [])
                    if git_repos:
                        for repo in git_repos:
                            st.markdown(f"- [{repo}]({repo})")
                    else:
                        st.info("Nessuna repository GitHub esplicita trovata.")
                    
                else:
                    st.error(f"Errore restituito dal Backend: {response.json().get('detail')}")
            except requests.exceptions.ConnectionError:
                st.error("Connessione fallita. Assicurati che 'backend.py' sia attivo nel terminale sulla porta 8000.")