import streamlit as st
import requests
import pandas as pd

# ============================================================
# COMPONENTI NON DICHIARATI CON VULNERABILITÀ
# ============================================================

def render_component_not_declared_vuln(backend_url: str):
    st.markdown("---")

    st.subheader("Componenti non dichiarati con vulnerabilità")

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

        non_declared_vulnerable = data.get(
            "non_declared_vulnerable_components",
            0
        )

        percentage = data.get(
            "percentage",
            0
        )

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(
                "Componenti vulnerabili",
                total_vulnerable
            )

        with col2:
            st.metric(
                "Non dichiarati vulnerabili",
                non_declared_vulnerable
            )

        with col3:
            st.metric(
                "% non dichiarati vulnerabili",
                f"{percentage:.2f}%"
            )