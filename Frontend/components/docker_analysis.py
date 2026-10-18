import streamlit as st
import requests
import json
import pandas as pd
import re
from streamlit_agraph import agraph, Node, Edge, Config

def format_source_files(files):
    normal_files = set()
    steps = []

    for file_data in files:
        if isinstance(file_data, dict):
            file = file_data.get("source", "")
        else:
            file = file_data

        if not file:
            continue

        match = re.search(r"step_(\d+)_sbom\.json", file, re.IGNORECASE)

        if match:
            steps.append(int(match.group(1)))
        else:
            normal_files.add(file)

    result = []

    if normal_files:
        result.append("File: " + ", ".join(sorted(normal_files)))

    if steps:
        steps = sorted(set(steps))
        ranges = []
        start = end = steps[0]

        for step in steps[1:]:
            if step == end + 1:
                end = step
            else:
                ranges.append((start, end))
                start = end = step

        ranges.append((start, end))

        formatted_steps = []

        for start, end in ranges:
            if start == end:
                formatted_steps.append(f"Step {start}")
            else:
                formatted_steps.append(f"Step {start}–{end}")

        result.append("Dockerfile: " + ", ".join(formatted_steps))

    return " | ".join(result)

def render_docker_section(backend_url: str):
    st.subheader("Sezione di Analisi Immagine Docker")
    
    docker_choice = st.session_state.get("config_docker_choice", "Genera SBOM Docker")
    docker_image_tag = st.session_state.get("config_docker_image_tag", "paperlessngx/paperless-ngx:dev")
    vuln_type = st.session_state.get("config_vuln_type", "os,library")
    docker_file = st.session_state.get("config_docker_uploader", None)
    build_from_dockerfile = st.checkbox(
        "Costruisci l'immagine dal Dockerfile del repository (invece di usare quella pubblicata)",
        value=True,
        key="docker_build_from_dockerfile",
    )
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
                            "vuln_type": vuln_type,
                            "build_from_dockerfile": build_from_dockerfile
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
                                st.session_state["docker_analyzed_image"] = response_data.get("analyzed_image")
                            else:
        
                                # Fallback: se l'utente non ha premuto il Bottone 1, creiamo la struttura minima
                                st.session_state.analysis_results = {
                                    "result": [],
                                    "docker_report": response_data["docker_report"],
                                    "raw_docker_sbom": response_data.get("raw_docker_sbom", ""),
                                    "docker_analyzed_image": response_data.get("analyzed_image")
                                }
                        st.session_state["docker_results"]["deps_dev_edges"] = (response_data.get("deps_dev_edges", []))
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
    #if st.session_state.docker_analyzed and current_docker_report and current_docker_report.get("total_docker_packages", 0) > 0:
    if st.session_state.docker_analyzed and current_docker_report:    
        st.markdown("#### 📊 Statistiche e Deviazioni dell'Immagine Docker")
        analyzed_image = st.session_state.get("docker_analyzed_image")
        if analyzed_image:
            st.caption(f"Immagine analizzata: `{analyzed_image}`")  
            
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
        
        with st.expander(f"📌 Pacchetti totali nel Docker ({current_docker_report.get('total_docker_packages', 0)})"):
            if current_docker_report.get("docker_components"):
                data = []
                for item in current_docker_report["docker_components"]:
                    data.append({
                        "Componente": item["name"],
                        "Versione": item["version"],
                        "PURL": item.get("purl", "-")
                    })
                st.dataframe(pd.DataFrame(data), use_container_width=True)
            else:
                st.info("Nessun pacchetto rilevato.")
        
        with st.expander(f"✅ Pacchetti comuni tra Docker e Sorgente ({current_docker_report.get('packages_in_common_count', 0)})"):
            if current_docker_report.get("in_common"):
                
                data = []
                for item in current_docker_report["in_common"]:
                    data.append({
                        "Componente": item["name"],
                        "Versione": item["version"],
                        "PURL": item.get("purl", "-"),
                        "File Sorgente (oltre a immagine docker)": format_source_files(item.get("source_files", []))
                    })
                st.dataframe(pd.DataFrame(data), use_container_width=True)
            else:
                st.info("Nessuna corrispondenza trovata.")
        
        
        with st.expander(f"⚠️ Pacchetti solo dentro l'Immagine Docker ({current_docker_report.get('packages_only_in_docker_count', 0)})"):
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
        
        with st.expander(f"❗ Pacchetti con Versioni Differenti ({len(current_docker_report.get('version_mismatches', []))})"):
            mismatches = current_docker_report.get("version_mismatches", [])
            if mismatches:
                df_mismatch = pd.DataFrame([
                    {
                        "Componente": m["docker"]["name"],
                        "Versione Docker": m["docker"].get("version", "-"),
                        "Versione Sorgente": m.get("code_version", "-"),
                        "File Sorgente": format_source_files(m.get("source_files", []))
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
                        "File Sorgente (oltre a immagine docker)": format_source_files(m.get("files", []))
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
            
    # --- GRAFO DELLE DIPENDENZE DOCKER ---
    docker_results = st.session_state.get("docker_results", {})
    docker_graph = docker_results.get("graphs", {})
    deps_dev_edges = docker_results.get("deps_dev_edges", [])
    hierarchy_weights = docker_results.get("hierarchy_with_weights", {})

    if st.session_state.docker_analyzed and docker_graph:
        st.divider()
        st.subheader("Grafo delle dipendenze Docker")

        st.markdown(
            """
            **Legenda**

            - 🔵 Arco blu: relazione già presente nel grafo originale.
            - 🟠 Arco arancione: relazione aggiunta tramite `deps.dev`.
            - 🟡 Nodo giallo: componente selezionato nella ricerca.
            """
        )

        deps_dev_edge_set = {
            (edge.get("source"), edge.get("target"))
            for edge in deps_dev_edges
            if edge.get("source") and edge.get("target")
        }

        component_options = sorted(
            docker_graph.keys(),
            key=lambda purl: purl.lower()
        )

        selected_component = st.selectbox(
            "Cerca un componente da evidenziare",
            options=["Tutti i componenti"] + component_options,
            format_func=lambda purl: (
                purl if purl == "Tutti i componenti"
                else purl.split("/")[-1]
            ),
            key="docker_graph_component_search"
        )

        total_nodes = len(docker_graph)
        total_edges = sum(len(children) for children in docker_graph.values())

        col1, col2, col3 = st.columns(3)
        col1.metric("Componenti", total_nodes)
        col2.metric("Archi totali", total_edges)
        col3.metric("Archi da deps.dev", len(deps_dev_edges))

        # Se viene selezionato un componente, mostra i suoi archi
        # in ingresso e in uscita, così la visualizzazione rimane leggibile.
        visible_edges = []

        for source, children in docker_graph.items():
            for target in children:
                if (
                    selected_component == "Tutti i componenti"
                    or source == selected_component
                    or target == selected_component
                ):
                    visible_edges.append((source, target))

        if selected_component == "Tutti i componenti":
            visible_nodes = set(docker_graph.keys())
        else:
            visible_nodes = {selected_component}
            for source, target in visible_edges:
                visible_nodes.add(source)
                visible_nodes.add(target)

        # Assegna identificatori semplici per evitare problemi
        # con i caratteri speciali contenuti nei PURL.
        node_ids = {
            purl: f"n{i}"
            for i, purl in enumerate(sorted(visible_nodes))
        }

        def dot_escape(value):
            return (
                str(value)
                .replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("\n", " ")
            )

        nodes = []
        edges = []

        # Crea i nodi solo per i componenti visibili.
        for purl in sorted(visible_nodes):
            label = purl.split("/")[-1]

            if "@" in label:
                label = label.rsplit("@", 1)[0]

            selected = purl == selected_component

            nodes.append(
                Node(
                    id=purl,
                    label=label,
                    title=purl,
                    size=25 if selected else 15,
                    color="#FFD966" if selected else "#D9E2F3",
                    shape="dot",
                    font={"size": 12}
                )
            )

        # Crea gli archi e distingue quelli recuperati da deps.dev.
        for source, target in visible_edges:
            recovered = (source, target) in deps_dev_edge_set

            edges.append(
                Edge(
                    source=source,
                    target=target,
                    color="#E67E22" if recovered else "#2878B5",
                    width=3 if recovered else 1,
                    arrows="to",
                    title=(
                        "Arco recuperato tramite deps.dev"
                        if recovered
                        else "Arco del grafo originale"
                    )
                )
            )

        config = Config(
            width="100%",
            height=650,
            directed=True,
            physics=False,
            hierarchical=False,
            nodeHighlightBehavior=True,
            highlightColor="#FFD966",
            collapsible=False
        )

        agraph(
            nodes=nodes,
            edges=edges,
            config=config
        )

        # Tabella complementare per ispezionare le relazioni con precisione.
        with st.expander("Dettaglio degli archi"):
            edge_rows = []

            for source, target in visible_edges:
                edge_rows.append({
                    "Componente padre": source,
                    "Dipendenza": target,
                    "Origine": (
                        "🟠 deps.dev"
                        if (source, target) in deps_dev_edge_set
                        else "🔵 Grafo originale"
                    )
                })

            if edge_rows:
                st.dataframe(
                    pd.DataFrame(edge_rows),
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info(
                    "Il componente selezionato non ha archi da visualizzare."
                )

        # Pesi calcolati dal backend sul grafo già completato.
        with st.expander("Pesi dei componenti"):
            weight_rows = []

            for purl, details in hierarchy_weights.items():
                if (
                    selected_component == "Tutti i componenti"
                    or purl == selected_component
                ):
                    weight_rows.append({
                        "Componente": purl,
                        "Peso": details.get("weight", 0),
                        "Sovrapposizioni": details.get("overlap", 0)
                    })

            if weight_rows:
                st.dataframe(
                    pd.DataFrame(weight_rows),
                    use_container_width=True,
                    hide_index=True
                )