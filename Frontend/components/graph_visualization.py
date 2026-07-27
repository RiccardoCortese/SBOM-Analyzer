import streamlit as st
import pandas as pd
from streamlit_agraph import agraph, Node, Edge, Config

def render_graph_section(backend_url: str):
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
        