import streamlit as st
import requests
import pandas as pd


# ============================================================
# COMPONENTI NON DICHIARATI CON VULNERABILITÀ
# ============================================================

def render_component_not_declared_vuln(backend_url: str):

    st.markdown("---")

    st.subheader(
        "Componenti non dichiarati con vulnerabilità"
    )

    if st.button(
        "Analizza componenti non dichiarati vulnerabili",
        key="analyze_non_declared_vulnerable"
    ):

        try:

            response = requests.get(
                f"{backend_url}/non-declared-vulnerable-components"
            )

            if response.status_code == 200:

                data = response.json()

                if data.get("status") == "success":

                    st.session_state[
                        "non_declared_vulnerable_data"
                    ] = data

                else:

                    st.error(
                        data.get(
                            "message",
                            "Errore durante l'analisi."
                        )
                    )

            else:

                st.error(
                    f"Errore backend: HTTP {response.status_code}"
                )

        except Exception as e:

            st.error(
                f"Errore nella richiesta al backend: {e}"
            )

    # ============================================================
    # METRICHE
    # ============================================================

    if "non_declared_vulnerable_data" in st.session_state:

        data = st.session_state[
            "non_declared_vulnerable_data"
        ]

        total_vulnerable = data.get(
            "total_vulnerable_components",
            0
        )

        unknown_vulnerable = data.get(
            "unknown_vulnerable_count",
            0
        )

        transitive_unknown_vulnerable = data.get(
            "transitive_unknown_vulnerable_count",
            0
        )

        unknown_or_transitive_unknown = data.get(
            "unknown_or_transitive_unknown_count",
            0
        )

        percentage = data.get(
            "percentage_unknown_or_transitive_unknown",
            0
        )

        col1, col2, col3, col4 = st.columns(4)

        with col1:

            st.metric(
                "Componenti vulnerabili",
                total_vulnerable
            )

        with col2:

            st.metric(
                "Vulnerabili sconosciuti",
                unknown_vulnerable
            )

        with col3:

            st.metric(
                "Vulnerabili transitivi sconosciuti",
                transitive_unknown_vulnerable
            )

        with col4:

            st.metric(
                "% sconosciuti / transitivi sconosciuti",
                f"{percentage:.2f}%"
            )

        # ========================================================
        # COMPONENTI VULNERABILI UNKNOWN
        # ========================================================

        unknown_components = data.get(
            "unknown_vulnerable_components",
            []
        )

        if unknown_components:

            st.markdown(
                "### Componenti vulnerabili sconosciuti"
            )

            rows = []

            for component in unknown_components:

                rows.append({
                    "Componente": component.get(
                        "name",
                        "unknown"
                    ),
                    "Versione": component.get(
                        "version",
                        "unknown"
                    ),
                    "PURL": component.get(
                        "purl",
                        "-"
                    ),
                    "CVE": ", ".join(
                        component.get(
                            "cves",
                            []
                        )
                    )
                })

            df_unknown = pd.DataFrame(rows)

            st.dataframe(
                df_unknown,
                use_container_width=True,
                hide_index=True
            )

        # ========================================================
        # COMPONENTI VULNERABILI TRANSITIVE UNKNOWN
        # ========================================================

        transitive_unknown_components = data.get(
            "transitive_unknown_vulnerable_components",
            []
        )

        if transitive_unknown_components:

            st.markdown(
                "### Componenti vulnerabili transitivi sconosciuti"
            )

            rows = []

            for component in transitive_unknown_components:

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
                    "PURL": component.get(
                        "purl",
                        "-"
                    ),
                    "CVE": ", ".join(
                        component.get(
                            "cves",
                            []
                        )
                    )
                })

            df_transitive_unknown = pd.DataFrame(rows)

            st.dataframe(
                df_transitive_unknown,
                use_container_width=True,
                hide_index=True
            )

        # ========================================================
        # NESSUN COMPONENTE UNKNOWN / TRANSITIVE UNKNOWN
        # ========================================================

        if unknown_or_transitive_unknown == 0:

            st.info(
                "Non sono stati trovati componenti vulnerabili "
                "classificati come sconosciuti o transitivi sconosciuti."
            )
