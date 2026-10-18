import streamlit as st
import requests
import pandas as pd
import json

# ============================================================
# RQ1: CONFRONTO SBOM SORGENTE E IMMAGINE FINALE
# ============================================================

def render_source_image_sbom_comparison(backend_url: str):

    st.subheader("Confronto SBOM: sorgente vs immagine finale")

    st.write(
        "Confronta i componenti rilevati da Trivy nello SBOM del sorgente "
        "e nello SBOM dell'immagine Docker finale, mostrando le vulnerabilità "
        "associate a ciascuna categoria."
    )

    st.info(
        "Le categorie indicano in quale SBOM è stato rilevato un componente. "
        "Non implicano automaticamente che il componente sia stato aggiunto "
        "o rimosso durante la build."
    )

    if st.button(
        "Confronta SBOM e analizza vulnerabilità",
        key="run_source_image_comparison",
        use_container_width=True,
    ):
        with st.spinner(
            "Confronto degli SBOM e scansione delle vulnerabilità in corso..."
        ):
            try:
                response = requests.get(
                    f"{backend_url}/compare-source-image-sboms",
                    timeout=900,
                )

                if response.status_code == 200:
                    st.session_state[
                        "source_image_comparison_results"
                    ] = response.json()

                    st.success("Confronto completato.")
                else:
                    try:
                        error_message = response.json().get(
                            "detail",
                            "Errore sconosciuto",
                        )
                    except Exception:
                        error_message = response.text

                    st.error(
                        f"Errore durante il confronto: {error_message}"
                    )

            except requests.exceptions.Timeout:
                st.error(
                    "Timeout: il confronto o le scansioni Trivy "
                    "hanno richiesto troppo tempo."
                )
            except requests.exceptions.RequestException as e:
                st.error(f"Errore di connessione al backend: {e}")

    result = st.session_state.get(
        "source_image_comparison_results"
    )

    if not result:
        st.caption(
            "Avvia il confronto per visualizzare i componenti "
            "e le relative vulnerabilità."
        )
        return

    summary = result.get("summary", {})
    categories = result.get("categories", {})

    # --------------------------------------------------------
    # RIEPILOGO GENERALE
    # --------------------------------------------------------

    st.markdown("### Riepilogo del confronto")

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric(
        "Componenti sorgente",
        summary.get("source_components", 0),
    )
    col2.metric(
        "Componenti immagine",
        summary.get("image_components", 0),
    )
    col3.metric(
        "Solo sorgente",
        summary.get("source_only", 0),
    )
    col4.metric(
        "Solo immagine",
        summary.get("image_only", 0),
    )
    col5.metric(
        "In comune",
        summary.get("common", 0),
    )

    # --------------------------------------------------------
    # DOWNLOAD JSON COMPLETO
    # --------------------------------------------------------

    st.download_button(
        label="Scarica report completo JSON",
        data=json.dumps(result, indent=2, ensure_ascii=False),
        file_name="source_image_sbom_comparison.json",
        mime="application/json",
        key="download_source_image_comparison",
    )

    # --------------------------------------------------------
    # TRE CATEGORIE
    # --------------------------------------------------------

    category_config = [
        (
            "Solo nel sorgente",
            "source_only",
            "Componenti rilevati nello SBOM del sorgente ma non "
            "nello SBOM dell'immagine finale.",
        ),
        (
            "Solo nell'immagine",
            "image_only",
            "Componenti rilevati nello SBOM dell'immagine finale ma "
            "non nello SBOM del sorgente.",
        ),
        (
            "In comune",
            "common",
            "Componenti rilevati in entrambi gli SBOM.",
        ),
    ]

    tabs = st.tabs([item[0] for item in category_config])

    for tab, (title, category_key, description) in zip(
        tabs, category_config
    ):
        with tab:

            category_data = categories.get(category_key, {})
            components = category_data.get("components", [])

            st.markdown(f"### {title}")
            st.caption(description)

            # ------------------------------------------------
            # METRICHE DELLA CATEGORIA
            # ------------------------------------------------

            m1, m2, m3 = st.columns(3)

            m1.metric(
                "Componenti",
                category_data.get("total_components", len(components)),
            )
            m2.metric(
                "Con vulnerabilità",
                category_data.get("vulnerable_components", 0),
            )
            m3.metric(
                "Componenti vulnerabili (%)",
                f"{category_data.get('components_with_vulnerabilities_pct', 0):.2f}%",
            )

            severity_counts = category_data.get("severity_counts", {})

            if severity_counts:
                st.markdown("#### Vulnerabilità per severità")

                sev_cols = st.columns(5)
                for col, severity in zip(
                    sev_cols,
                    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
                ):
                    col.metric(
                        severity,
                        severity_counts.get(severity, 0),
                    )
            else:
                st.caption(
                    "Nessuna vulnerabilità associata ai componenti "
                    "di questa categoria."
                )

            st.divider()

            if not components:
                st.info("Nessun componente in questa categoria.")
                continue

            # ------------------------------------------------
            # FILTRI
            # ------------------------------------------------

            filter_col1, filter_col2 = st.columns(2)

            with filter_col1:
                search_text = st.text_input(
                    "Cerca componente",
                    key=f"search_{category_key}",
                    placeholder="Nome, versione o PURL...",
                )

            with filter_col2:
                severity_filter = st.multiselect(
                    "Severità delle vulnerabilità",
                    options=[
                        "CRITICAL",
                        "HIGH",
                        "MEDIUM",
                        "LOW",
                        "UNKNOWN",
                    ],
                    key=f"severity_{category_key}",
                )

            filtered_components = []

            for component in components:

                searchable_text = " ".join([
                    str(component.get("name") or ""),
                    str(component.get("version") or ""),
                    str(component.get("purl") or ""),
                ]).lower()

                if (
                    search_text
                    and search_text.lower() not in searchable_text
                ):
                    continue

                vulnerabilities = component.get(
                    "vulnerabilities", []
                )

                if severity_filter:
                    vulnerabilities = [
                        vulnerability
                        for vulnerability in vulnerabilities
                        if vulnerability.get("severity") in severity_filter
                    ]

                    # Se è stata scelta una severità, mostra solo i componenti
                    # che hanno almeno una vulnerabilità con quella severità.
                    if not vulnerabilities:
                        continue

                filtered_component = dict(component)
                filtered_component[
                    "filtered_vulnerabilities"
                ] = vulnerabilities

                filtered_components.append(filtered_component)

            st.markdown(
                f"#### Componenti trovati: {len(filtered_components)}"
            )

            # ------------------------------------------------
            # TABELLA COMPONENTI
            # ------------------------------------------------

            table_rows = []

            for component in filtered_components:
                table_rows.append({
                    "Nome": component.get("name") or "N/D",
                    "Versione": component.get("version") or "N/D",
                    "PURL": component.get("purl") or "N/D",
                    "Vulnerabilità": len(
                        component.get("vulnerabilities", [])
                    ),
                    "Severità massima": component.get(
                        "max_severity", "UNKNOWN"
                    ),
                    "Stato scansione": component.get(
                        "scan_status", "N/D"
                    ),
                })

            if table_rows:
                st.dataframe(
                    pd.DataFrame(table_rows),
                    use_container_width=True,
                    hide_index=True,
                )

            # ------------------------------------------------
            # DETTAGLIO COMPONENTI E CVE
            # ------------------------------------------------
            with st.expander(
                "Mostra dettagli componenti e vulnerabilità",
                expanded=False,
            ):
                st.markdown("#### Dettaglio vulnerabilità")

                for component in filtered_components:

                    vulnerabilities = component.get(
                        "filtered_vulnerabilities", []
                    )

                    name = component.get("name") or "Componente senza nome"
                    version = component.get("version") or "versione sconosciuta"

                    with st.expander(
                        f"{name} — {version} "
                        f"({len(vulnerabilities)} vulnerabilità)",
                        expanded=False,
                    ):

                        st.write(
                            f"**PURL:** `{component.get('purl') or 'N/D'}`"
                        )

                        st.write(
                            f"**Severità massima:** "
                            f"{component.get('max_severity', 'UNKNOWN')}"
                        )

                        st.write(
                            f"**Stato scansione:** "
                            f"{component.get('scan_status', 'N/D')}"
                        )

                        if vulnerabilities:
                            for vulnerability in vulnerabilities:

                                severity = vulnerability.get(
                                    "severity", "UNKNOWN"
                                )
                                cve_id = vulnerability.get("id", "N/D")

                                st.markdown(
                                    f"**{cve_id} — {severity}**"
                                )

                                if vulnerability.get("title"):
                                    st.write(vulnerability["title"])

                                installed_version = vulnerability.get(
                                    "installed_version"
                                )
                                fixed_version = vulnerability.get(
                                    "fixed_version"
                                )

                                st.write(
                                    f"Versione installata: "
                                    f"`{installed_version or version}`"
                                )

                                st.write(
                                    f"Versione corretta: "
                                    f"`{fixed_version or 'Non indicata da Trivy'}`"
                                )

                                primary_url = vulnerability.get("primary_url")
                                if primary_url:
                                    st.markdown(
                                        f"[Dettagli della vulnerabilità]({primary_url})"
                                    )

                                st.divider()

                        else:
                            st.write(
                                "Nessuna vulnerabilità associata al componente "
                                "nella scansione eseguita."
                            )