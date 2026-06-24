import streamlit as st
import requests
import pandas as pd
import json
from streamlit_agraph import agraph, Node, Edge, Config

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
    st.session_state.saved_branch = "main"
if "saved_format" not in st.session_state:
    st.session_state.saved_format = "entrambi"
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = None
if "deep_sbom_results" not in st.session_state:
    st.session_state.deep_sbom_results = None
if "docker_analyzed" not in st.session_state:
    st.session_state.docker_analyzed = False

# ============================================================
# CONFIGURAZIONE TARGET & SBOM DI BASE (Repo + SBOM Base + Docker)
# ============================================================
st.subheader("1. Configurazione Target & SBOM di Base")

repo_url = st.text_input("GitHub Repository URL", value=st.session_state.saved_repo, placeholder="https://github.com/owner/repo")
branch = st.text_input("Branch", value=st.session_state.saved_branch)
st.info("⚡ Inserisci la URL della repository GitHub e il branch da analizzare.")
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
    # Se l'utente sceglie di caricare un file SBOM Docker, mostriamo il file uploader
    
    docker_file = st.file_uploader("Carica lo SBOM dell'immagine Docker", type=["json"])

elif docker_choice == "Genera SBOM Docker":
    # Se l'utente sceglie di generare lo SBOM Docker, mostriamo i campi per il tag dell'immagine e il tipo di vulnerabilità da scansionare
         
    docker_image_tag = st.text_input(
        "Tag Immagine / Nome Dockerfile custom:",
        value="stfbk/tlsassistant:v3.2-dev3",
        placeholder="es. stfbk/tlsassistant:v3.2-dev2-ACN o ./docker/Dockerfile"
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
    st.info("⚡ Verrà inviato questo target alla pipeline remota di GitHub Actions.")

st.markdown("---")

# ============================================================
# SBOM STATICO (generazione o upload)
# ============================================================

sbom_choice = st.radio(
    "Scegli l'origine dello SBOM di base:",
    ["Genera SBOM Statico da zero", "Carica file SBOM esistenti"],
    horizontal=True
)

requirements_file = None
poetry_file = None

if sbom_choice == "Carica file SBOM esistenti":
    # Se l'utente sceglie di caricare file SBOM esistenti, mostriamo due file uploader affiancati per i formati requirements e poetry
    
    col1, col2 = st.columns(2)
    with col1:
        requirements_file = st.file_uploader("Carica JSON Requirements", type=["json"])
    with col2:
        poetry_file = st.file_uploader("Carica JSON Poetry", type=["json"])
        
elif sbom_choice == "Genera SBOM Statico da zero":
    # Se l'utente sceglie di generare lo SBOM da zero, mostriamo un selectbox per scegliere il formato da generare tramite la pipeline
    
    format_type = st.selectbox(
        "Seleziona il formato da generare tramite la pipeline:",
        options=["entrambi", "requirements", "poetry"],
        format_func=lambda x: x.capitalize()
    )
    
    st.session_state.saved_format = format_type

if st.button("🔄 Invia e Mantieni in Memoria sul Server"):
    if not repo_url:
        st.error("Inserisci la URL della repo.")
        st.stop()
        
    st.session_state.saved_repo = repo_url
    st.session_state.saved_branch = branch
    st.session_state.docker_analyzed = False  # Resetta lo stato se cambiano i file target

    with st.spinner("Salvataggio file sul server..."):
        try:
            data_payload = {"action": "generate" if sbom_choice == "Genera SBOM Statico da zero" else "upload"}
            files_payload = {}
            
            if requirements_file: files_payload["requirements_file"] = requirements_file.getvalue()
            if poetry_file: files_payload["poetry_file"] = poetry_file.getvalue()
            if docker_file: files_payload["docker_file"] = docker_file.getvalue() 
            
            res = requests.post(f"{BACKEND_URL}/upload-sbom", data=data_payload, files=files_payload)
                
            if res.status_code == 200:
                st.session_state.sbom_ready = True
                st.success(res.json().get("message"))
                st.rerun()
            else:
                st.error(f"Errore server: {res.text}")
        except Exception as e:
            st.error(f"Errore di connessione: {str(e)}")

st.markdown("---")

# ============================================================
# ANALISI COMPARATIVA DINAMICA & DEEP INSPECTION
# ============================================================
if st.session_state.sbom_ready:
   
    st.subheader("2. Analisi Comparativa Dinamica")

    path_dipendenze = st.text_input(
        "Nome del file delle dipendenze dinamiche nella repo:",
        value="dependencies.json"
    ).strip()

    btn_col1, btn_col2 = st.columns(2)

    with btn_col1:
        
        if st.button("📊 Genera Tabella di Confronto Base", use_container_width=True):
            
            with st.spinner("Calcolo tabella in corso..."):
        
                try:
        
                    fmt = st.session_state.saved_format if sbom_choice == "Genera SBOM Statico da zero" else "manual_only"
                    res = requests.post(
                        # Endpoint di confronto che restituisce la matrice di confronto e i risultati per il rendering
                        f"{BACKEND_URL}/compare-dependencies",
                        params={
                            "repo_url": st.session_state.saved_repo,
                            "branch": st.session_state.saved_branch,
                            "path_dipendenze": path_dipendenze,
                            "format": fmt,
                        },
                    )
                    
                    # risposta di successo: aggiorna lo stato con i risultati dell'analisi per il rendering dinamico della tabella e dei KPI
                    if res.status_code == 200:
                        
                        st.session_state.analysis_results = res.json()
                        st.success("Tabella di confronto generata!")
                        st.rerun()
                    
                    else:
                    
                        st.error(f"Errore dal server FastAPI: {res.text}")
                        st.session_state.analysis_results = None
                
                except Exception as e:
        
                    st.error(f"Errore durante l'elaborazione: {str(e)}")
                    st.session_state.analysis_results = None

    with btn_col2:
        
        # Pulsante per avviare la Deep Inspection (analisi riga per riga di ogni sottodipendenza)
        if st.button("🔍 Avvia Deep Inspection (Genera SBOM Dipendenze)", use_container_width=True):
        
            with st.spinner("Trivy sta analizzando ogni singola sottodipendenza..."):
        
                try:
        
                    res = requests.post(
                        f"{BACKEND_URL}/analyze-dependencies-sbom",
                        params={
                            "repo_url": st.session_state.saved_repo,
                            "branch": st.session_state.saved_branch,
                            "path_dipendenze": path_dipendenze,
                        },
                    )
        
                    if res.status_code == 200:
        
                        st.session_state.deep_sbom_results = res.json()
                        st.success("Deep Inspection completata! Ora puoi scaricare gli SBOM riga per riga.")
        
                    else:
        
                        st.error(f"Errore dal server: {res.text}")
                        st.session_state.deep_sbom_results = None
                        
                except Exception as e:
                    
                    st.error(f"Errore di connessione: {str(e)}")
                    st.session_state.deep_sbom_results = None

    # DIPENDENZE DEL CODICE (SORGENTE)
    if st.session_state.analysis_results is not None:
        
        result = st.session_state.analysis_results
        dependencies = result.get("result", [])
        git_repos = [item["url"] for item in dependencies if item.get("url") and "github.com" in item["url"]]
        comparison_report = result.get("comparison_matrix", None)
        raw_req = result.get("raw_requirements", None)
        raw_poe = result.get("raw_poetry", None)
        component_type = result.get("component_type", None)
        
        # Estrazione dinamica del report ad ogni ciclo di esecuzione dello stato
        docker_report = result.get("docker_report", {})

        st.markdown("---")
        
        # ============================================================
        # TABELLONE DINAMICO DI CONFRONTO (con possibilità di download dei singoli SBOM riga per riga)
        # ============================================================    
        st.markdown("### 📦 Elenco Dipendenze Rilevate nel Codice")
        
        if dependencies:
           
            col_tipo, col_comp, col_type, col_sorg, col_req, col_poe, col_az = st.columns([1, 2, 1.5, 3, 1.5, 1.5, 1.5])
            with col_tipo: st.markdown("**Tipo**")
            with col_comp: st.markdown("**Componente**")
            with col_type: st.markdown("**Tipo Componente**")
            with col_sorg: st.markdown("**Sorgente / PURL**")
            with col_req:  st.markdown("**In Requirements**")
            with col_poe:  st.markdown("**In Poetry**")
            with col_az:   st.markdown("**SBOM**")
            st.markdown("---")

            for idx, item in enumerate(dependencies):
                
                # Estrazione dinamica dei dati di ogni dipendenza, con gestione
                c_tipo = item.get("type", "-")
                c_name = item.get("name", "-")
                c_type = item.get("component_type", "-")
                c_url  = item.get("url", "-")
                c_req  = item.get("present_in_requirements", "❌")
                c_poe  = item.get("present_in_poetry", "❌")
                
                # Creazione dinamica di una riga per ogni dipendenza, con possibilità di scaricare lo SBOM specifico di quella riga se disponibile
                r_tipo, r_comp, r_type, r_sorg, r_req, r_poe, r_az = st.columns([1, 2, 1.5, 3, 1.5, 1.5, 1.5])
                with r_tipo: st.write(c_tipo)
                with r_comp: st.write(c_name)
                with r_type: st.write(c_type)
                with r_sorg: st.write(c_url)
                with r_req:  st.write(c_req)
                with r_poe:  st.write(c_poe)
                
                with r_az: # Logica per il download dello SBOM specifico di quella dipendenza (se disponibile)
           
                    clean_repo_name = c_url.replace("https://github.com/", "").replace("/", "-").replace(".git", "")
                    
                    deep_results = st.session_state.get("deep_sbom_results") or {}
                    available_sboms = deep_results.get("sboms", {})
                    
                    # Cerchiamo una chiave che contenga il nome pulito della repo, considerando che il backend potrebbe aver aggiunto suffissi o prefissi
                    matching_key = next((k for k in available_sboms.keys() if clean_repo_name in k), None)
                    
                    if matching_key:
                        st.download_button(
                            label="⬇️ SBOM",
                            data=available_sboms[matching_key],
                            file_name=matching_key, 
                            mime="application/json",
                            key=f"dl_row_{clean_repo_name}_{idx}",
                            use_container_width=True
                        )
                    else:
                        st.button(
                            label="🚫 Non Disp.", 
                            key=f"disabled_row_{idx}", 
                            disabled=True,
                            use_container_width=True
                        )

        # ============================================================
        # SEZIONE DI ANALISI IMMAGINE DOCKER 
        # ============================================================
        st.markdown("---")
        st.subheader("🐳 Sezione di Analisi Immagine Docker")
        
        if docker_choice == "Genera SBOM Docker":
            
            if st.button("🐳 Avvia Generazione Pipeline & Confronto Docker", use_container_width=True):
            
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
            
                                st.session_state["docker_results"] = {"graphs": response_data["graphs"]}
                            
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
            
                    # Se carichi manualmente lo SBOM, ci assicuriamo che esista un contenitore in session_state
                    if st.session_state.analysis_results is None:
            
                        st.session_state.analysis_results = {"result": [], "docker_report": {}}
                    
                    try:
                        # Parsing del file caricato dall'utente e inserimento nello stato
                        uploaded_content = json.loads(docker_file.getvalue().decode("utf-8"))
                        # Qui ipotizziamo che il backend abbia già popolato il "docker_report" nell'endpoint /upload-sbom, 
                        # o gestisci il parsing del dizionario custom caricato.
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
            
            kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
            kpi1.metric("Totale Pacchetti nel Docker", current_docker_report.get("total_docker_packages", 0))
            kpi2.metric("✅ In Comune con i Sorgenti", current_docker_report.get("packages_in_common_count", 0))
            kpi3.metric("⚠️ Esclusivi Docker", current_docker_report.get("packages_only_in_docker_count", 0))
            kpi4.metric("❗ Versioni Differenti (Tra Docker e Sorgenti)", current_docker_report.get("packages_with_version_mismatches_count", 0))
            kpi5.metric("❌ Mancanti nel Docker", current_docker_report.get("packages_missing_in_docker_count", 0))

            raw_docker_sbom = current_results.get("raw_docker_sbom", "")

            # Colonne per i bottoni di download
            dl_col1, dl_col2 = st.columns(2)
            
            with dl_col1:
                st.download_button(
                    label="⬇️ Scarica Report degli elementi SOLO nel Docker (JSON deviazioni)",
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
                            "File Sorgente": ", ".join(sources)
                        })
                    st.dataframe(pd.DataFrame(data), use_container_width=True)
                else:
                    st.info("Nessuna corrispondenza trovata.")
            
            
            with st.expander(f"🔴 Pacchetti solo dentro l'Immagine Docker ({current_docker_report.get('packages_only_in_docker_count', 0)})"):
                st. info("Questa sezione mostra i pacchetti presenti solo nell'immagine Docker. Si noti che alcune dipendenze possono essere presenti più volte con versioni diverse all'interno dello SBOM Docker. Questo perchè potrebbero esserci dei residui di build.")
               
                if current_docker_report.get("only_in_docker"):
            
                    st.dataframe(pd.DataFrame(current_docker_report["only_in_docker"]), use_container_width=True)
            
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
                st. info("Questa sezione mostra le dipendenze che sono presenti nei sorgenti della repository ma non sono state rilevate nell'immagine Docker. Questo può indicare che alcune librerie non sono state incluse nella build dell'immagine.")
                missing_in_docker = current_docker_report.get("missing_in_docker", [])
                
                if missing_in_docker:
                    # Trasformiamo la lista di dizionari in un DataFrame leggibile
                    df_missing = pd.DataFrame([
                        {
                            "Componente": m.get("name", "-"),
                            "Versione Sorgente": m.get("version", "-"),
                            "PURL": m.get("purl", "-"),
                            "File Sorgente": ", ".join(m.get("files", []))
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
            # Unione dei grafi che arrivano da analisi diverse (Repo o Docker)
            repo_graphs = st.session_state.get("deep_sbom_results", {}).get("graphs", {})
            docker_graphs = st.session_state.get("docker_results", {}).get("graphs", {})
            
            
            # Combiniamo i due dizionari
            all_graphs = {**repo_graphs, **docker_graphs}
            
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
                
                # Creazione nodi e archi
                nodes = [Node(id=n["id"], label=n["label"], size=15) for n in graph_data["nodes"]]
                edges = [Edge(source=e["source"], target=e["target"]) for e in graph_data["edges"]]
                
                is_hierarchical = (modalita == "Albero Gerarchico") # Se l'utente sceglie la modalità ad albero, abilitiamo il layout gerarchico
                
                config = Config(
                    height=500, 
                    width=700, 
                    directed=True, 
                    physics=not is_hierarchical, # Physics meno invasiva se è albero
                    hierarchical=is_hierarchical,
                    nodeHighlightBehavior=True,
                    highlightColor="#F7A7A6"
                )
                
                agraph(nodes=nodes, edges=edges, config=config)
            
            else:
            
                st.info("Esegui un'analisi (Repo o Docker) per generare i grafi.")
        # ============================================================
        # TAB DI TRASPARENZA IN CODA (LOGS E FILE COMPLETI)
        # ============================================================
        st.markdown("---")
        st.subheader("📋 Log di Controllo e File di Configurazione Generati")
        
        tab_labels = ["🔗 Link GitHub Sorgenti"]
        if comparison_report: tab_labels.append("🔍 Matrice di Confronto (Pipeline)")
        if raw_req: tab_labels.append("📋 Trivy Requirements JSON")
        if raw_poe: tab_labels.append("📋 Trivy Poetry JSON")
        tab_labels.append("📄 JSON grezzo analizzato backend")

        tabs = st.tabs(tab_labels)
        current_tab_idx = 0
        
        with tabs[current_tab_idx]:
           
            if git_repos:
           
                for r in sorted(list(set(git_repos))): 
                    # Se la URL è valida, rendila cliccabile; altrimenti, visualizzala come testo normale
                    st.markdown(f"- [{r}]({r})" if r.startswith("http") else f"- {r}")
            
            else: st.info("Nessuna repository GitHub mappata.")
        current_tab_idx += 1

        if comparison_report:

            with tabs[current_tab_idx]:

                if result.get("github_run_url"): 
                    st.markdown(f"🌐 [Link Run Actions]({result.get('github_run_url')})")

                st.text_area("Log di Confronto:", value=comparison_report, height=250)

            current_tab_idx += 1

        if raw_req:
            
            with tabs[current_tab_idx]:
            
                st.download_button(
                    label="⬇️ Scarica Trivy Requirements JSON",
                    data=raw_req if isinstance(raw_req, str) else json.dumps(raw_req, indent=2),
                    file_name="trivy_requirements.json",
                    mime="application/json",
                    key="dl_tab_requirements"
                )
                st.code(raw_req, language="json")
            current_tab_idx += 1

        if raw_poe:
            
            with tabs[current_tab_idx]:
                st.download_button(
                    label="⬇️ Scarica Trivy Poetry JSON",
                    data=raw_poe if isinstance(raw_poe, str) else json.dumps(raw_poe, indent=2),
                    file_name="trivy_poetry.json",
                    mime="application/json",
                    key="dl_tab_poetry"
                )
                st.code(raw_poe, language="json")
            current_tab_idx += 1

        with tabs[current_tab_idx]:
            st.code(json.dumps(result, indent=2), language="json")

else:
    st.warning("⚠️ Completa il punto precedente e clicca su 'Invia e Mantieni in Memoria sul Server' per sbloccare l'analisi.")