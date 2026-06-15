import streamlit as st
import requests
import pandas as pd

st.set_page_config(page_title="SBOM Frontend", layout="wide")
st.title("SBOM Analyzer")

# URL del Backend FastAPI
BACKEND_URL = "http://127.0.0.1:8000"

uploaded_file = st.file_uploader("Trascina qui il file dependency.json", type=["json"])

if uploaded_file is not None:
    if st.button("Invia al Backend per Analisi"):
        with st.spinner("Il Backend sta elaborando i dati e lanciando Trivy..."):
            
            # file da inviare via API
            files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/json")}
            
            try:
                # Chiamata REST API al backend
                response = requests.post(BACKEND_URL + "/analyze", files=files)
                
                if response.status_code == 200:
                    result_json = response.json()
                    
                    st.success("Analisi completata con successo dal Backend!")
                    
                    # Tabella Riassuntiva
                    st.subheader("Dipendenze Manuali Rilevate")
                    deps_data = result_json.get("dependencies", [])
                    if deps_data:
                        df = pd.DataFrame(deps_data)
                        df.columns = ["Nome Tool", "Versione", "PURL", "Linguaggio", "GitHub Repository"]
                        st.dataframe(df, use_container_width=True)
                    else:
                        st.info("Nessuna dipendenza trovata.")
                    
                else:
                    st.error(f"Il backend ha restituito un errore: {response.text}")
                    
            except requests.exceptions.ConnectionError:
                st.error("Impossibile connettersi al Backend. Assicurati che backend.py sia avviato su sulla porta 8000!")