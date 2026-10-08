import streamlit as st
import requests
import pandas as pd


def get_classification_color(classification):
    colors = {
        "declared": "#4CAF50",
        "transitive": "#2196F3",
        "transitive_unknown": "#FF9800",
        "unknown": "#9E9E9E"
    }

    return colors.get(
        classification,
        "#9E9E9E"
    )


def get_classification_label(classification):
    labels = {
        "declared": "Dichiarata",
        "transitive": "Transitiva",
        "transitive_unknown": "Transitiva sconosciuta",
        "unknown": "Sconosciuta"
    }

    return labels.get(
        classification,
        "Sconosciuta"
    )


def style_classification(value):
    color = get_classification_color(value)

    return (
        f"background-color: {color}; "
        "color: white; "
        "font-weight: bold; "
        "text-align: center;"
    )


def render_component_provenance(backend_url: str):
    
    if "dockerfile_analysis" not in st.session_state:
        st.session_state.dockerfile_analysis = None
    if "source_component_analysis" not in st.session_state:
        st.session_state.source_component_analysis = None
        
    st.subheader("Provenienza dei componenti")

    # ============================================================
    # COMPONENTI INTRODOTTI DAL DOCKERFILE
    # ============================================================

    if st.button("Ricerca componenti introdotti da Dockerfile che non sono presenti nei manifest", use_container_width=True):
        try:
            res = requests.get(f"{backend_url}/component-provenance-dockerfile")

            if res.status_code != 200:
                st.error(f"Errore durante l'analisi della provenienza: {res.status_code}")
                return

            data = res.json()

            if data.get("status") != "success":
                st.error("Analisi della provenienza non riuscita.")
                return
            else:
                st.session_state.dockerfile_analysis = data
        except requests.RequestException as e:
            st.error(f"Errore di connessione al backend: {e}")
            
        
    data = st.session_state.dockerfile_analysis
    
    if data is not None:
        manifest_components = data.get("manifest_components",{})

        docker_components = data.get("docker_components", {})

        if docker_components:

            st.markdown("### Componenti introdotti durante la build")

            st.info(
                "Questi componenti sono stati introdotti durante "
                "gli step del Dockerfile e non sono presenti nei "
                "manifest del progetto."
            )

            rows = []

            for purl, component in docker_components.items():

                dependency_chain = component.get(
                    "dependency_chain",
                    []
                )

                rows.append({
                    "Componente": component.get(
                        "name",
                        "unknown"
                    ),
                    "Versione": component.get(
                        "version",
                        "unknown"
                    ),
                    "Deriva da": component.get(
                        "derived_from",
                        "-"
                    ),
                    "Catena dipendenze": (
                        " → ".join(dependency_chain)
                        if dependency_chain
                        else "-"
                    ),
                    "Step Docker": component.get(
                        "origin_step",
                        "-"
                    ),
                    "File SBOM": component.get(
                        "origin_file",
                        "-"
                    ),
                    "PURL": purl
                })

            st.dataframe(
                rows,
                use_container_width=True,
                hide_index=True
            )

        else:
            st.info("Non sono stati trovati componenti introdotti durante gli step Docker.")

        

    # ============================================================
    # COMPONENTI NON PRESENTI NEI MANIFEST
    # ============================================================

    if st.button("Analizza i componenti non presenti nei manifest", use_container_width=True):
        try:
            res = requests.get(f"{backend_url}/source-component-analysis")

            if res.status_code != 200:
                st.error(
                    f"Errore durante l'analisi dei componenti dai manifest: "
                    f"{res.status_code}"
                )
                return

            data = res.json()

            if data.get("status") != "success":
                st.error("Analisi dei componenti dai manifest non riuscita.")
                return
            else:
                st.session_state.source_component_analysis = data

        except requests.RequestException as e:
            st.error(f"Errore di connessione al backend: {e}")

    data = st.session_state.source_component_analysis

    if data is not None:
        not_declared = data.get(
            "not_declared",
            []
        )

        stats = data.get(
            "stats",
            {}
        )

        # ----------------------------------------------------
        # LEGENDA
        # ----------------------------------------------------

        st.markdown("#### Classificazione")

        legend = pd.DataFrame({
            "Categoria": [
                "Dichiarata",
                "Transitiva",
                "Transitiva sconosciuta",
                "Sconosciuta"
            ],
            "Significato": [
                "Dipendenza dichiarata direttamente nei manifest",
                "Dipendenza derivata da una componente dichiarata, anche attraverso più livelli",
                "Dipendenza derivata da una componente sconosciuta, anche attraverso più livelli",
                "Componente senza una relazione di dipendenza identificabile"
            ]
        })

        st.dataframe(
            legend,
            use_container_width=True,
            hide_index=True
        )

        # ----------------------------------------------------
        # STATISTICHE
        # ----------------------------------------------------

        if stats:
            st.markdown("#### Statistiche")

            col1, col2, col3, col4 = st.columns(4)

            col1.metric(
                "Dichiarate",
                stats.get("declared_in_sbom", 0)
            )

            col2.metric(
                "Transitive",
                stats.get("transitive", 0)
            )

            col3.metric(
                "Transitive sconosciute",
                stats.get("transitive_unknown", 0)
            )

            col4.metric(
                "Sconosciute",
                stats.get("unknown", 0)
            )

        # ----------------------------------------------------
        # TABELLA
        # ----------------------------------------------------

        if not_declared:

            st.markdown(
                "### Componenti non presenti nei manifest"
            )

            st.info(
                "I colori nella colonna Classificazione indicano "
                "la provenienza della componente."
            )

            rows = []

            for component in not_declared:

                dependency_chain = component.get(
                    "dependency_chain",
                    []
                )

                classification = component.get(
                    "classification",
                    "unknown"
                )

                rows.append({
                    "Componente": component.get(
                        "name",
                        "unknown"
                    ),
                    "Versione": component.get(
                        "version",
                        "unknown"
                    ),
                    "Classificazione": get_classification_label(
                        classification
                    ),
                    "Deriva da": component.get(
                        "derived_from",
                        "-"
                    ),
                    "Catena dipendenze": (
                        " → ".join(dependency_chain)
                        if dependency_chain
                        else "-"
                    ),
                    "PURL": component.get(
                        "purl",
                        "-"
                    )
                })

            df = pd.DataFrame(rows)

            styled_df = df.style.map(
                lambda value: style_classification(
                    {
                        "Dichiarata": "declared",
                        "Transitiva": "transitive",
                        "Transitiva sconosciuta": "transitive_unknown",
                        "Sconosciuta": "unknown"
                    }.get(
                        value,
                        "unknown"
                    )
                ),
                subset=["Classificazione"]
            )

            st.dataframe(
                styled_df,
                use_container_width=True,
                hide_index=True
            )

        else:
            st.info(
                "Non sono stati trovati componenti non presenti "
                "nei manifest del progetto."
            )