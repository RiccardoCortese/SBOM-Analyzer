import streamlit as st
import requests
import pandas as pd
import json
from streamlit_agraph import agraph, Node, Edge, Config
import re

# ============================================================
# CONFIGURAZIONE APP STREAMLIT
# ============================================================

st.set_page_config(page_title="SBOM Analyzer", layout="wide")
st.title("SBOM Analyzer")

BACKEND_URL = "http://127.0.0.1:8000"

# ============================================================
# STATE MANAGEMENT (Streamlit session_state)
# Serve per mantenere lo stato tra return della UI
# ============================================================
# Inizializzazione Stati Permanenti di Streamlit
if "sbom_ready" not in st.session_state:
    st.session_state.sbom_ready = False
if "saved_repo" not in st.session_state:
    st.session_state.saved_repo = ""
if "saved_branch" not in st.session_state:
    st.session_state.saved_branch = "dev"
if "saved_format" not in st.session_state:
    st.session_state.saved_format = "entrambi"
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = {}
if "merged_results" not in st.session_state:
    st.session_state.merged_results = None
if "analysis_results_standard" not in st.session_state:
    st.session_state.analysis_results_standard = None
if "analysis_results_advanced" not in st.session_state:
    st.session_state.analysis_results_advanced = False
if "deep_sbom_results" not in st.session_state:
    st.session_state.deep_sbom_results = None
if "docker_analyzed" not in st.session_state:
    st.session_state.docker_analyzed = False
if "docker_results" not in st.session_state:
    st.session_state.docker_results = {"graphs": {}, "hierarchy_with_weights": {}}

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
            res = requests.post(f"{BACKEND_URL}/upload-sbom", data=data_payload, files=files_payload)
            if res.status_code == 200:
                risposta = res.json()
                st.success(f"Configurazione accettata: {risposta.get('message')}")
                
                if "files" in risposta:
                    st.session_state.found_files = risposta.get("files", [])
                    st.session_state.steps = risposta.get("steps", [])
                    st.session_state.images = risposta.get("images", [])
                    st.info(f"Ho trovato {len(st.session_state.found_files)} file di dipendenze.")
                st.rerun()
            else:
                # Se il backend fallisce, mostriamo l'errore specifico
                error_msg = res.json().get("detail", "Errore sconosciuto")
                st.error(f"Discovery Fallita: {error_msg}")
                st.warning("Suggerimento: Verifica che il percorso del Dockerfile sia corretto o passa alla modalità Manuale.")
        except Exception as e:
            st.error(f"Errore di connessione: {str(e)}")
            
if "found_files" in st.session_state and st.session_state.found_files:
    # Recuperiamo le analisi dal session_state (se le hai salvate lì dal backend)
    
    st.subheader("📦 File di dipendenze rilevati")
    
    # Visualizzazione dinamica
    for file_name in st.session_state.found_files:
        st.markdown(f"📄 **{file_name}**")
    
    if "steps" in st.session_state and st.session_state.steps:
        st.subheader("Passaggi Docker rilevati")
        for step in st.session_state.steps:
            st.code(f"{step}", language="docker")
    else:
        st.info("Nessun passaggio Docker rilevato.")

    if "images" in st.session_state and st.session_state.images:
        st.subheader("Immagini Docker rilevate")
        for img in st.session_state.images:
            st.code(f"FROM {img}", language="docker")
    else:
        st.info("Nessuna immagine Docker rilevata.")
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
                    f"{BACKEND_URL}/analyze-standard-file",
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
                        f"{BACKEND_URL}/analyze-custom-file",
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

st.subheader("Calcolo Grafi e Merge Artefatti")
col1, col2 = st.columns([1, 1])

with col1:
    st.info("Clicca qui per unire gli artefatti")
    if st.button("Unisci Artefatti SBOM", use_container_width=True):
        with st.spinner("Unione artefatti in corso..."):
            try:
                res_merge = requests.get(f"{BACKEND_URL}/merge-artifacts")
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
                res_graphs = requests.get(f"{BACKEND_URL}/generate-graphs")
                if res_graphs.status_code == 200:
                    graph_data = res_graphs.json()
                    st.session_state.deep_sbom_results = graph_data
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
st.subheader("Sezione di Analisi Immagine Docker")

if docker_choice == "Genera SBOM Docker":
    
    if st.button("Avvia Generazione Pipeline & Confronto Docker", use_container_width=True):
    
        with st.spinner("Compilazione immagine in corso su GitHub Actions e analisi Trivy..."):
    
            try:
    
                res_docker = requests.post(
                    f"{BACKEND_URL}/generate-docker-sbom",
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

# ============================================================
# TAB DI VISUALIZZAZIONE GRAFICA DELLE DIPENDENZE
# ============================================================
st.markdown("---")
st.subheader("Analisi delle Dipendenze (Grafo & Albero)")

with st.container():

    if not st.session_state.deep_sbom_results:
        st.info("Esegui un'analisi Docker per generare i grafi delle dipendenze.")
        st.stop()
    # Unione dei grafi che arrivano da analisi diverse (Repo o Docker)
    repo_graphs = st.session_state.get("deep_sbom_results", {}).get("graphs", {})
    docker_graphs = st.session_state.get("docker_results", {}).get("graphs", {})
    hierarchy_with_weights = st.session_state.get("docker_results", {}).get("hierarchy_with_weights", {})
    hierarchy_with_weights_merged = {**st.session_state.get("graph_results", {}).get("hierarchy_with_weights", {}), **hierarchy_with_weights}
    
    normalized_docker_graphs = {}
    for purl, deps in docker_graphs.items():
        # normalizzazone dei nodi e archi per il grafo Docker
        normalized_docker_graphs["Docker_SBOM"] = {
            "nodes": [{"id": purl, "label": purl.split('/')[-1].split('@')[0]} for purl in docker_graphs.keys()],
            "edges": [{"source": parent, "target": child} for parent, children in docker_graphs.items() for child in children]
        }
    
    # Unione dei due dizionari
    all_graphs = {**repo_graphs, **normalized_docker_graphs}
    #all_graphs = normalized_docker_graphs  # Al momento consideriamo solo il grafo Docker per la visualizzazione
    if all_graphs:
        col_a, col_b = st.columns([2, 1])
        with col_a:
            file_selezionato = st.selectbox(
                "Seleziona lo SBOM da visualizzare:", 
                options=list(all_graphs.keys()),
                key="grafo_select"
            )
        with col_b:
            modalita = st.radio("Layout:", ["Grafo Libero", "Albero Gerarchico"], horizontal=True)
    
        graph_data = all_graphs[file_selezionato]
        
        # Creazione di un dizionario per rimuovere eventuali nodi duplicati, risultato del merge tra file diversi
        unique_nodes = {}

        for n in graph_data["nodes"]:
            unique_nodes[n["id"]] = n

        nodes = [
            Node(id=n["id"], label=n["label"], size=15)
            for n in unique_nodes.values()
        ]
        edges = [Edge(source=e["source"], target=e["target"]) for e in graph_data["edges"]]
        
        is_hierarchical = (modalita == "Albero Gerarchico") # Se l'utente sceglie la modalità ad albero, abilitiamo il layout gerarchico
        
        config = Config(
            height=500, 
            width="100%", 
            directed=True, 
            physics=not is_hierarchical, # Physics meno invasiva se è albero
            hierarchical=is_hierarchical,
            nodeHighlightBehavior=True,
            highlightColor="#F7A7A6"
        )
        
        agraph(nodes=nodes, edges=edges, config=config)

        
        # ============================================================
        # SEZIONE DI ANALISI DEL PESO DELLE DIPENDENZE
        # ============================================================
        
        if file_selezionato == "Docker_SBOM" or file_selezionato == "final_merged_sbom.json":
            if file_selezionato == "final_merged_sbom.json":
                print("Usando i pesi uniti per il grafico finale")
                hierarchy_with_weights = hierarchy_with_weights_merged
            elif file_selezionato == "Docker_SBOM":
                print("Usando i pesi Docker per il grafico Docker")
                hierarchy_with_weights = hierarchy_with_weights
            
            st.divider()
            st.subheader("📊 Analisi Impatto Dipendenze")
            
            with st.expander("Analisi del peso delle dipendenze"):
                # Preparazione dati per la tabella
                impact_data = [
                    {
                        "Pacchetto": purl.split('/')[-1].split('@')[0], 
                        "Peso (Dipendenze Totali)": data.get("weight", 0),
                        "Dipendenze Sovrapposte": str(data.get("overlap", 0))
                    } 
                    for purl, data in hierarchy_with_weights.items()
                ]
                
                
                df = pd.DataFrame(impact_data)
                
                # Filtriamo solo i pacchetti con peso maggiore di 0 e ordiniamo per peso decrescente
                df_filtered = df[df["Peso (Dipendenze Totali)"] > 0].sort_values(
                    by="Peso (Dipendenze Totali)", 
                    ascending=False
                    )
                
                # Conversione della colonna Pacchetto in una categoria ordinata così da mantenere l'ordine nel grafico a barre
                df_filtered["Pacchetto"] = pd.Categorical(
                    df_filtered["Pacchetto"], 
                    categories=df_filtered["Pacchetto"].unique(), 
                    ordered=True
                    )
                
                # visualizzazione a barre del peso delle dipendenze
                chart_data = df_filtered.set_index("Pacchetto")[["Peso (Dipendenze Totali)"]]
                
                # visualizzazione a barre colorata
                st.bar_chart(chart_data)
                
                # Tabella dettagliata
                st.dataframe(df_filtered, use_container_width=True)
        
            
                st.info("Il 'peso' indica quante dipendenze (dirette e indirette) ogni pacchetto trascina con sé. Le dipendenze sovrapposte rappresentano quelle condivise con altri pacchetti.")
    
    else:
    
        st.info("Esegui un'analisi (Repo o Docker) per generare i grafi.")
    