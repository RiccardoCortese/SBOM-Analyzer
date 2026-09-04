import streamlit as st
import pandas as pd
from streamlit_agraph import agraph, Node, Edge, Config


# ============================================================
# COLORI DISPONIBILI
# ============================================================

GROUP_COLORS = {
    "Python": "#FFD166",
    "Debian": "#4D96FF",
    "Node.js": "#6BCB77",
    "Maven": "#FF6B6B",
    "Go": "#9B5DE5",
    "Rust": "#F9844A",
    "Altro": "#AAAAAA"
}


def get_package_group(purl):
    """
    Determina la tipologia del pacchetto in base al PURL.
    """

    if purl.startswith("pkg:pypi/"):
        return "Python"

    elif purl.startswith("pkg:deb/"):
        return "Debian"

    elif purl.startswith("pkg:npm/"):
        return "Node.js"

    elif purl.startswith("pkg:maven/"):
        return "Maven"

    elif purl.startswith("pkg:golang/"):
        return "Go"

    elif purl.startswith("pkg:cargo/"):
        return "Rust"

    else:
        return "Altro"


def render_graph_section(backend_url: str):

    st.markdown("---")
    st.subheader("Analisi delle Dipendenze (Grafo & Albero)")

    with st.expander("📌 Visualizzazione Grafica delle Dipendenze", expanded=False):

        with st.container():

            if not st.session_state.deep_sbom_results:
                st.info("Esegui un'analisi Docker per generare i grafi delle dipendenze.")
                st.stop()

            # ============================================================
            # RECUPERO DEI GRAFI
            # ============================================================

            repo_graphs = st.session_state.get("deep_sbom_results", {}).get("graphs", {})

            docker_graphs = st.session_state.get("docker_results", {}).get("graphs", {})

            hierarchy_with_weights = st.session_state.get("docker_results", {}).get("hierarchy_with_weights", {})

            hierarchy_with_weights_merged = {
                **st.session_state.get(
                    "graph_results", {}
                ).get("hierarchy_with_weights", {}),
                **hierarchy_with_weights
            }

            # ============================================================
            # NORMALIZZAZIONE GRAFO DOCKER
            # ============================================================

            normalized_docker_graphs = {}

            for purl, deps in docker_graphs.items():

                normalized_docker_graphs["Docker_SBOM"] = {
                    "nodes": [
                        {
                            "id": purl,
                            "label": purl.split("/")[-1].split("@")[0]
                        }
                        for purl in docker_graphs.keys()
                    ],
                    "edges": [
                        {
                            "source": parent,
                            "target": child
                        }
                        for parent, children in docker_graphs.items()
                        for child in children
                    ]
                }

            # ============================================================
            # UNIONE DEI GRAFI
            # ============================================================

            all_graphs = {
                **repo_graphs,
                **normalized_docker_graphs
            }

            if all_graphs:

                col_a, col_b = st.columns([2, 1])

                with col_a:

                    file_selezionato = st.selectbox(
                        "Seleziona lo SBOM da visualizzare:",
                        options=list(all_graphs.keys()),
                        key="grafo_select"
                    )

                with col_b:

                    modalita = st.radio(
                        "Layout:",
                        ["Grafo Libero", "Albero Gerarchico"],
                        horizontal=True
                    )

                graph_data = all_graphs[file_selezionato]

                # ============================================================
                # RIMOZIONE NODI DUPLICATI
                # ============================================================

                unique_nodes = {}

                for n in graph_data["nodes"]:
                    unique_nodes[n["id"]] = n

                # ============================================================
                # DETERMINAZIONE DEI GRUPPI PRESENTI
                # ============================================================

                groups_present = set()

                for n in unique_nodes.values():
                    purl = n["id"]
                    group = get_package_group(purl)
                    groups_present.add(group)

                # Manteniamo un ordine fisso nella legenda
                group_order = [
                    "Python",
                    "Debian",
                    "Node.js",
                    "Maven",
                    "Go",
                    "Rust",
                    "Altro"
                ]

                groups_present = [
                    group
                    for group in group_order
                    if group in groups_present
                ]

                # ============================================================
                # CREAZIONE NODI COLORATI
                # ============================================================

                nodes = []

                for n in unique_nodes.values():

                    purl = n["id"]

                    group = get_package_group(purl)

                    color = GROUP_COLORS[group]

                    nodes.append(
                        Node(
                            id=purl,
                            label=n["label"],
                            size=15,
                            color=color
                        )
                    )

                # ============================================================
                # CREAZIONE ARCHI
                # ============================================================

                edges = [
                    Edge(
                        source=e["source"],
                        target=e["target"]
                    )
                    for e in graph_data["edges"]
                ]

                # ============================================================
                # CONFIGURAZIONE LAYOUT
                # ============================================================

                is_hierarchical = (modalita == "Albero Gerarchico")

                config = Config(
                    height=500,
                    width="100%",
                    directed=True,
                    physics=not is_hierarchical,
                    hierarchical=is_hierarchical,
                    nodeHighlightBehavior=True,
                    highlightColor="#F7A7A6"
                )

                # ============================================================
                # VISUALIZZAZIONE GRAFO
                # ============================================================

                agraph(
                    nodes=nodes,
                    edges=edges,
                    config=config
                )

                # ============================================================
                # LEGENDA DINAMICA
                # ============================================================

                if groups_present:

                    st.markdown("**Legenda:**")

                    legend_cols = st.columns(len(groups_present))

                    for col, group in zip(legend_cols, groups_present):

                        with col:

                            color = GROUP_COLORS[group]

                            st.markdown(
                                f"<span style='color:{color}; font-size:20px;'>●</span> {group}",
                                unsafe_allow_html=True
                            )

                # ============================================================
                # ANALISI IMPATTO DIPENDENZE
                # ============================================================

                if (file_selezionato == "Docker_SBOM" or file_selezionato == "final_merged_sbom.json"):

                    if file_selezionato == "final_merged_sbom.json":

                        print("Usando i pesi uniti per il grafico finale")

                        hierarchy_with_weights = (hierarchy_with_weights_merged)

                    elif file_selezionato == "Docker_SBOM":

                        print("Usando i pesi Docker per il grafico Docker")

                        hierarchy_with_weights = (hierarchy_with_weights)

                    st.divider()

                    st.subheader("📊 Analisi Impatto Dipendenze")

                    with st.expander("Analisi del peso delle dipendenze"):

                        impact_data = [
                            {
                                "Pacchetto": purl.split("/")[-1].split("@")[0],
                                "Peso (Dipendenze Totali)": data.get("weight", 0),
                                "Dipendenze Sovrapposte": str(
                                    data.get("overlap", 0)
                                )
                            }
                            for purl, data in hierarchy_with_weights.items()
                        ]

                        df = pd.DataFrame(impact_data)

                        df_filtered = df[
                            df["Peso (Dipendenze Totali)"] > 0
                        ].sort_values(
                            by="Peso (Dipendenze Totali)",
                            ascending=False
                        )

                        df_filtered["Pacchetto"] = pd.Categorical(
                            df_filtered["Pacchetto"],
                            categories=df_filtered["Pacchetto"].unique(),
                            ordered=True
                        )

                        chart_data = df_filtered.set_index("Pacchetto")[["Peso (Dipendenze Totali)"]]

                        st.bar_chart(chart_data)

                        st.dataframe(df_filtered, width="stretch")

                        st.info(
                            "Il 'peso' indica quante dipendenze "
                            "(dirette e indirette) ogni pacchetto trascina "
                            "con sé. Le dipendenze sovrapposte rappresentano "
                            "quelle condivise con altri pacchetti."
                        )

            else:

                st.info("Esegui un'analisi (Repo o Docker) per generare i grafi.")