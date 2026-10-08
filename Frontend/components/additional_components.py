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

def render_additional_components(backend_url: str):

    st.subheader("Componenti aggiuntivi rispetto alla scansione classica (RQ1 / RQ1.1)")


    st.info(
        "Confronta la baseline (sorgente + immagine Docker finale) con i componenti "
        "individuati dall'analisi del Dockerfile e ne scansiona le vulnerabilità."
    )

    include_removed = st.checkbox(
        "Includi i componenti rimossi dal Dockerfile",
        value=False,
        key="additional_include_removed",
        help="Se selezionata, i componenti installati e poi rimossi nel Dockerfile "
                "vengono considerati tra gli aggiuntivi (e scansionati)."
    )

    if st.button("Analizza componenti aggiuntivi", use_container_width=True):
        with st.spinner("Analisi componenti aggiuntivi in corso..."):
            try:
                res = requests.get(
                    f"{backend_url}/additional-components-analysis",
                    params={"include_removed": include_removed},
                    timeout=600,
                )

                if res.status_code == 200:
                    st.session_state.additional_results = res.json()
                    st.success("Analisi completata!")
                    st.rerun()
                else:
                    error_msg = res.json().get("detail", "Errore sconosciuto")
                    st.error(f"Analisi fallita: {error_msg}")
            except Exception as e:
                st.error(f"Errore di connessione: {str(e)}")

    results = st.session_state.get("additional_results")
    if not results:
        return

    rq1 = results.get("rq1", {})
    rq1_1 = results.get("rq1_1", {})
    additional = results.get("additional_components", [])
    vulnerable = results.get("vulnerable_additional_components", [])


    # ========================================================
    # RQ1
    # ========================================================
    st.markdown("### RQ1: quanti componenti in più individuiamo?")

    st.markdown("#### Analisi classica")

    m1, m2, m3 = st.columns(3)

    m1.metric(
        "Componenti da sorgente",
        rq1.get("source_components", 0),
        help=(
            "Numero di componenti unici individuati analizzando gli SBOM "
            "generati direttamente dalla sorgente del progetto "
            "(ad esempio requirements.txt, pom.xml, build.gradle, ecc.)."
        )
    )

    m2.metric(
        "Componenti da immagine Docker",
        rq1.get("image_components", 0),
        help=(
            "Numero di componenti unici individuati analizzando lo SBOM "
            "dell'immagine Docker finale."
        )
    )

    m3.metric(
        "Merge (componenti unici)",
        rq1.get("baseline_components", 0),
        help=(
            "Numero di componenti unici ottenuti dall'unione tra i componenti "
            "della sorgente e quelli dell'immagine Docker finale. "
            "I componenti presenti in entrambe le fonti vengono conteggiati una sola volta."
        )
    )


    st.markdown("#### Nostra metodologia")

    m5, m6, m7 = st.columns(3)

    m5.metric(
        "Totale componenti rilevati",
        rq1.get("methodology_components", 0),
        help=(
            "Numero totale di componenti unici individuati dalla metodologia. "
            "Comprende i componenti della sorgente, dell'immagine Docker finale "
            "e i componenti aggiuntivi individuati analizzando gli step del Dockerfile."
        )
    )

    m6.metric(
        "Componenti aggiuntivi rilevati",
        rq1.get("additional_components", 0),
        help=(
            "Numero di componenti individuati dagli step del Dockerfile "
            "che non erano già presenti nella baseline, cioè nell'unione "
            "tra sorgente e immagine Docker finale."
        )
    )

    m7.metric(
        "Componenti aggiuntivi / totale",
        f"{rq1.get('pct_additional_vs_methodology', 0)}%",
        help=(
            "Percentuale dei componenti aggiuntivi rispetto al totale dei "
            "componenti individuati dalla metodologia. "
            "Formula: componenti aggiuntivi / totale componenti rilevati × 100."
        )
    )

    '''
    by_eco = rq1.get("additional_by_ecosystem", {})
    if by_eco:
        st.markdown("**Aggiuntivi per ecosistema**")
        df_eco = pd.DataFrame(
            {"Ecosistema": list(by_eco.keys()), "Componenti": list(by_eco.values())}
        ).set_index("Ecosistema")
        st.bar_chart(df_eco)
    '''
    # ========================================================
    # RQ1.1
    # ========================================================
    st.markdown("### RQ1.1: quanti aggiuntivi sono vulnerabili?")

    v1, v2, v3, v4 = st.columns(4)
    v1.metric("Scansionati", rq1_1.get("scanned_components", 0))
    v2.metric("Vulnerabili", rq1_1.get("vulnerable_additional_components", 0))
    v3.metric("% su aggiuntivi", f"{rq1_1.get('vulnerable_pct_of_additional', 0)}%")
    v4.metric("CVE uniche", rq1_1.get("unique_cves", 0))

    st.caption(f"% sui soli componenti scansionati: {rq1_1.get('vulnerable_pct_of_scanned', 0)}%")

    # Componenti senza purl o senza versione (Trivy non può associare CVE)
    not_scannable = rq1_1.get("not_scannable_no_purl_or_version", 0)
    if not_scannable:
        st.warning(
            f"{not_scannable} componenti aggiuntivi non sono scansionabili perché privi di "
            "purl o di versione (es. pacchetti installati senza versione nel Dockerfile)."
        )

    # Gruppi (librerie, deb, apk, rpm) la cui scansione Trivy è fallita
    for err in rq1_1.get("scan_errors", []):
        st.error(
            f"Scansione fallita per il gruppo '{err.get('group')}' "
            f"({err.get('components')} componenti): {err.get('error')}"
        )

    by_group = rq1_1.get("scanned_by_group", {})
    if by_group:
        st.caption(
            "Componenti scansionati per gruppo: "
            + ", ".join(f"{g}: {n}" for g, n in by_group.items())
        )

    by_sev = rq1_1.get("by_max_severity", {})
    if by_sev:
        st.markdown("**Componenti vulnerabili per severità massima**")
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
    tab_vuln, tab_add = st.tabs(
        [f"Aggiuntivi vulnerabili ({len(vulnerable)})", f"Tutti gli aggiuntivi ({len(additional)})"]
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
                        "Origine": format_source_files(c.get("sources", [])),
                    }
                    for c in vulnerable
                ]
            )
            sev_filter = st.multiselect(
                "Filtra per severità",
                options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
                default=[],
                key="additional_sev_filter",
            )
            if sev_filter:
                df_vuln = df_vuln[df_vuln["Severità max"].isin(sev_filter)]
            st.dataframe(df_vuln, use_container_width=True, hide_index=True)
        else:
            st.info("Nessun componente aggiuntivo vulnerabile trovato.")

    with tab_add:
        if additional:
            df_add = pd.DataFrame(
                [
                    {
                        "Nome": c.get("name"),
                        "Versione": c.get("version"),
                        "Tipo": c.get("type"),
                        "PURL": c.get("purl"),
                        "Origine": format_source_files(c.get("sources", [])),
                    }
                    for c in additional
                ]
            )
            st.dataframe(df_add, use_container_width=True, hide_index=True)
        else:
            st.info("Nessun componente aggiuntivo trovato.")

    # ========================================================
    # DOWNLOAD
    # ========================================================
    suffix = "with_removed" if rq1.get("include_removed") else "without_removed"
    st.download_button(
        label="Scarica risultati RQ1 (JSON)",
        data=json.dumps(results, indent=2, ensure_ascii=False),
        file_name=f"rq1_results_{suffix}.json",
        mime="application/json",
    )