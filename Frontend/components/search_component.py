import streamlit as st
import requests
from streamlit_agraph import agraph, Node, Edge, Config


def render_search_component(backend_url: str):

    st.markdown("## 🔎 Ricerca Componente")

    col1, col2 = st.columns([1, 1])
    
    with col1:
        component = st.text_input(
            "Cerca nome componente",
        )

    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Cerca"):

            response = requests.get(
                f"{backend_url}/search-component",
                params={
                    "name": component
                }
            )


            if response.status_code == 200:

                data = response.json()
                st.session_state.component_graph = data

            else:
                st.error(response.text)


    if "component_graph" in st.session_state:
        st.info(f"Trovato in {len(st.session_state.component_graph['matches'])} SBOM")
        matches = st.session_state.component_graph["matches"]

        sbom_names = [
            item["sbom"]
            for item in matches
        ]

        selected = st.selectbox(
            "Seleziona SBOM:",
            sbom_names
        )
        item = next(
            x for x in matches 
            if x["sbom"] == selected
        )

        modalita = st.radio(
            "Visualizzazione:",
            ["Grafo libero", "Albero gerarchico"],
            horizontal=True
        )

        
        
        root_node = item["component"]["purl"]

        graph = item["graph"]

        nodes = [
            Node(
                id=n["id"],
                label=n["label"],
                size=15,
                color="#ff6666" if n["id"] == root_node else "#97c2fc"
            )
            for n in graph["nodes"]
        ]


        edges = [
            Edge(
                source=e["source"],
                target=e["target"]
            )
            for e in graph["edges"]
        ]


        is_tree = modalita == "Albero gerarchico"

        config = Config(
            height=500,
            width="100%",
            directed=True,
            physics=not is_tree,
            hierarchical=is_tree,
            nodeHighlightBehavior=True,
            highlightColor="#F7A7A6",
            collapsible=True
        )


        agraph(
            nodes=nodes,
            edges=edges,
            config=config
        )