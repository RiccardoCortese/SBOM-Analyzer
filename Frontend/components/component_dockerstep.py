import streamlit as st
import requests
import pandas as pd
import json
import re

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

def render_image_components_from_dockerfile(backend_url: str):
    st.subheader("Componenti dell'immagine riconducibili al Dockerfile (RQ1.2)")

    st.info(
        "Individua i componenti presenti nell'immagine Docker finale e negli "
        "SBOM dei singoli step del Dockerfile, ma assenti dagli SBOM del sorgente. "
        "Successivamente analizza le vulnerabilità dei soli componenti selezionati."
    )

    if st.button(
        "Analizza componenti dell'immagine",
        use_container_width=True,
        key="image_dockerfile_analyze",
    ):
        with st.spinner("Analisi dei componenti e delle vulnerabilità in corso..."):
            try:
                res = requests.get(
                    f"{backend_url}/image-components-from-dockerfile",
                    timeout=600,
                )

                if res.status_code == 200:
                    st.session_state.image_dockerfile_results = res.json()
                    st.success("Analisi completata!")
                    st.rerun()
                else:
                    try:
                        error_msg = res.json().get(
                            "detail", "Errore sconosciuto"
                        )
                    except Exception:
                        error_msg = res.text or "Errore sconosciuto"

                    st.error(f"Analisi fallita: {error_msg}")

            except Exception as e:
                st.error(f"Errore di connessione: {str(e)}")

    results = st.session_state.get("image_dockerfile_results")

    if not results:
        return

    rq = results.get("rq1_2", {})
    selected = results.get("selected_components", [])
    vulnerable = results.get("vulnerable_components", [])

    # ========================================================
    # RQ1.2 - SELEZIONE DEI COMPONENTI
    # ========================================================
    st.markdown(
        "### RQ1.2: quali componenti dell'immagine sono riconducibili "
        "agli step del Dockerfile?"
    )

    st.markdown("#### Componenti individuati dalle scansioni")

    m1, m2, m3 = st.columns(3)

    m1.metric(
        "Componenti da sorgente",
        rq.get("source_components", 0),
        help=(
            "Numero di componenti unici presenti negli SBOM generati "
            "analizzando il sorgente del progetto."
        ),
    )

    m2.metric(
        "Componenti da immagine finale",
        rq.get("image_components", 0),
        help=(
            "Numero di componenti unici rilevati nello SBOM "
            "dell'immagine Docker finale."
        ),
    )

    m3.metric(
        "Componenti negli step Dockerfile",
        rq.get("dockerfile_step_components", 0),
        help=(
            "Numero di componenti unici rilevati negli SBOM "
            "generati dai singoli step del Dockerfile."
        ),
    )

    st.markdown("#### Componenti selezionati per l'analisi")

    m4, m5, m6 = st.columns(3)

    m4.metric(
        "Componenti selezionati",
        rq.get("selected_components", 0),
        help=(
            "Componenti presenti sia nell'immagine finale sia negli SBOM "
            "degli step Dockerfile, ma assenti dallo SBOM del sorgente."
        ),
    )

    m5.metric(
        "Scansionati da Trivy",
        rq.get("scanned_components", 0),
        help=(
            "Componenti per i quali Trivy ha completato il processo "
            "di scansione secondo i criteri di riconoscimento del backend."
        ),
    )

    m6.metric(
        "Non riconosciuti da Trivy",
        rq.get("not_recognized_by_trivy", 0),
        help=(
            "Componenti non riconosciuti da Trivy durante la scansione. "
            "Non significa necessariamente che siano privi di vulnerabilità."
        ),
    )

    # ========================================================
    # RQ1.2 - VULNERABILITÀ
    # ========================================================
    st.markdown(
        "### Vulnerabilità dei componenti selezionati"
    )

    v1, v2, v3, v4 = st.columns(4)

    v1.metric(
        "Componenti vulnerabili",
        rq.get("vulnerable_components", 0),
    )

    v2.metric(
        "% vulnerabili",
        f"{rq.get('vulnerable_pct_of_selected', 0)}%",
        help=(
            "Percentuale dei componenti selezionati per i quali Trivy "
            "ha restituito almeno una vulnerabilità, rispetto al totale "
            "dei componenti selezionati."
        ),
    )

    v3.metric(
        "CVE uniche",
        rq.get("unique_cves", 0),
        help=(
            "Numero di identificativi CVE distinti rilevati "
            "nell'insieme dei componenti selezionati."
        ),
    )

    v4.metric(
        "Componenti selezionati",
        len(selected),
    )

    # Errori di scansione
    for err in rq.get("scan_errors", []):
        st.error(
            f"Scansione fallita per il gruppo '{err.get('group')}' "
            f"({err.get('components')} componenti): "
            f"{err.get('error')}"
        )

    # Grafico per severità
    by_sev = rq.get("by_max_severity", {})

    if by_sev:
        st.markdown("#### Componenti vulnerabili per severità massima")

        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

        df_sev = pd.DataFrame(
            {
                "Severità": [s for s in order if s in by_sev],
                "Componenti": [by_sev[s] for s in order if s in by_sev],
            }
        ).set_index("Severità")

        st.bar_chart(df_sev)

    # ========================================================
    # TABELLE
    # ========================================================
    tab_vuln, tab_all = st.tabs(
        [
            f"Componenti vulnerabili ({len(vulnerable)})",
            f"Tutti i componenti selezionati ({len(selected)})",
        ]
    )

    with tab_vuln:
        if vulnerable:
            df_vuln = pd.DataFrame(
                [
                    {
                        "Nome": c.get("name"),
                        "Versione": c.get("version"),
                        "Severità max": c.get("max_severity"),
                        "N. CVE": c.get("cve_count", 0),
                        "CVE": ", ".join(c.get("cves", [])),
                        "PURL": c.get("purl"),
                        "Origine": format_source_files(
                            c.get("sources", [])
                        ),
                    }
                    for c in vulnerable
                ]
            )

            sev_filter = st.multiselect(
                "Filtra per severità massima",
                options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
                default=[],
                key="image_dockerfile_sev_filter",
            )

            if sev_filter:
                df_vuln = df_vuln[
                    df_vuln["Severità max"].isin(sev_filter)
                ]

            search_vuln = st.text_input(
                "Cerca un componente vulnerabile",
                placeholder="Nome, versione, PURL o CVE...",
                key="image_dockerfile_search_vuln",
            )

            if search_vuln.strip():
                mask = df_vuln.astype(str).apply(
                    lambda col: col.str.contains(
                        search_vuln.strip(),
                        case=False,
                        regex=False,
                        na=False,
                    )
                ).any(axis=1)

                df_vuln = df_vuln[mask]

            st.dataframe(
                df_vuln,
                use_container_width=True,
                hide_index=True,
            )

            st.caption(
                "L'origine indica i file SBOM in cui il componente è stato "
                "rilevato. Per i dettagli sulle CVE, consulta i report "
                "generati da Trivy."
            )

        else:
            st.info(
                "Nessun componente vulnerabile trovato tra quelli selezionati."
            )

    with tab_all:
        if selected:
            df_all = pd.DataFrame(
                [
                    {
                        "Nome": c.get("name"),
                        "Versione": c.get("version"),
                        "Tipo": c.get("type"),
                        "PURL": c.get("purl"),
                        "Stato scansione": c.get("scan_status"),
                        "Origine": format_source_files(
                            c.get("sources", [])
                        ),
                    }
                    for c in selected
                ]
            )

            search_all = st.text_input(
                "Cerca un componente",
                placeholder="Nome, versione o PURL...",
                key="image_dockerfile_search_all",
            )

            if search_all.strip():
                mask = df_all.astype(str).apply(
                    lambda col: col.str.contains(
                        search_all.strip(),
                        case=False,
                        regex=False,
                        na=False,
                    )
                ).any(axis=1)

                df_all = df_all[mask]

            st.dataframe(
                df_all,
                use_container_width=True,
                hide_index=True,
            )

        else:
            st.info(
                "Nessun componente soddisfa i criteri di selezione. "
                "Devono essere presenti nell'immagine finale e negli step "
                "Dockerfile, ma assenti dallo SBOM del sorgente."
            )

    # ========================================================
    # DOWNLOAD
    # ========================================================
    st.markdown("### Esportazione dei risultati")

    st.download_button(
        label="Scarica risultati RQ1.2 (JSON)",
        data=json.dumps(results, indent=2, ensure_ascii=False),
        file_name="rq1_2_image_components_from_dockerfile.json",
        mime="application/json",
        use_container_width=True,
        key="image_dockerfile_download",
    )
