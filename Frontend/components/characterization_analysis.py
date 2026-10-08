import streamlit as st
import requests
import pandas as pd
import json

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

LABELS = {
    "declared": "Dichiarato",
    "transitive": "Transitivo",
    "unknown": "Sconosciuto diretto",
    "transitive_unknown": "Sconosciuto transitivo",
    "unmapped": "Non mappato",
    "absent": "Assente (SBOM classico)",
}


def render_characterization_analysis(backend_url: str):

    st.subheader("Valore della caratterizzazione dei componenti (RQ2)")

    st.info(
        "Analizza i componenti vulnerabili per categoria (dichiarati, transitivi, sconosciuti diretti "
        "e transitivi) e confronta la caratterizzazione con quella ottenibile dalla metodologia classica. "
        "Prima di avviarla esegui l'unione degli artefatti e la scansione delle vulnerabilità."
    )

    if st.button("Analizza caratterizzazione componenti", use_container_width=True):
        with st.spinner("Analisi della caratterizzazione in corso..."):
            try:
                res = requests.get(
                    f"{backend_url}/characterization-analysis",
                    timeout=600,
                )

                if res.status_code == 200:
                    st.session_state.characterization_results = res.json()
                    st.success("Analisi completata!")
                    st.rerun()
                else:
                    error_msg = res.json().get("detail", "Errore sconosciuto")
                    st.error(f"Analisi fallita: {error_msg}")
            except Exception as e:
                st.error(f"Errore di connessione: {str(e)}")

    results = st.session_state.get("characterization_results")
    if not results:
        return

    rq2_1 = results.get("rq2_1", {})
    rq2_2 = results.get("rq2_2", {})
    rq2_3 = results.get("rq2_3", {})
    target = results.get("target_components", [])

    # ========================================================
    # RQ2.1
    # ========================================================
    st.markdown("### RQ2.1: dichiarati e sconosciuti diretti sul totale dei vulnerabili")

    total = rq2_1.get("total_vulnerable_components", 0)

    a1, a2, a3, a4 = st.columns(4)
    a1.metric("Componenti vulnerabili", total)
    a2.metric("Dichiarati vulnerabili", rq2_1.get("declared_vulnerable", 0))
    a3.metric("Sconosciuti diretti vulnerabili", rq2_1.get("unknown_direct_vulnerable", 0))
    a4.metric(
        "Dichiarati + sconosciuti diretti",
        f"{rq2_1.get('declared_plus_unknown_direct', 0)} "
        f"({rq2_1.get('declared_plus_unknown_direct_pct', 0)}%)",
    )

    by_category = rq2_1.get("by_category", {})
    if by_category:
        df_cat = pd.DataFrame(
            [
                {
                    "Categoria": v.get("label", k),
                    "Componenti": v.get("count", 0),
                    "% sul totale": v.get("pct_of_total", 0),
                }
                for k, v in by_category.items()
            ]
        )
        c1, c2 = st.columns([1, 1])
        with c1:
            st.dataframe(df_cat, use_container_width=True, hide_index=True)
        with c2:
            st.bar_chart(df_cat.set_index("Categoria")["Componenti"])

        if by_category.get("unmapped", {}).get("count", 0) > 0:
            st.warning(
                "Alcuni componenti vulnerabili risultano 'Non mappati': sono presenti nel report "
                "Trivy ma non nell'analisi di caratterizzazione (possibile differenza nei purl)."
            )

    # ========================================================
    # RQ2.2
    # ========================================================
    st.markdown("### RQ2.2: severità dei dichiarati e sconosciuti diretti")

    target_sev = rq2_2.get("target_by_max_severity", {})
    all_sev = rq2_2.get("all_by_max_severity", {})
    pct_sev = rq2_2.get("target_pct_of_all_by_severity", {})

    s_cols = st.columns(len(SEVERITIES))
    for col, sev in zip(s_cols, SEVERITIES):
        col.metric(
            sev,
            target_sev.get(sev, 0),
            help=f"{pct_sev.get(sev, 0)}% dei {all_sev.get(sev, 0)} componenti {sev} totali",
        )

    st.caption(
        f"CRITICAL + HIGH nel gruppo: {rq2_2.get('critical_or_high_in_target', 0)} · "
        f"CVE uniche nel gruppo: {rq2_2.get('unique_cves_in_target', 0)}"
    )

    df_sev = pd.DataFrame(
        {
            "Severità": SEVERITIES,
            "Dichiarati + sconosciuti diretti": [target_sev.get(s, 0) for s in SEVERITIES],
            "Rimanenti vulnerabili": [all_sev.get(s, 0) - target_sev.get(s, 0) for s in SEVERITIES],
        }
    ).set_index("Severità")
    st.bar_chart(df_sev)

    sev_by_cat = rq2_2.get("severity_by_category", {})
    if sev_by_cat:
        with st.expander("Severità per categoria"):
            df_matrix = pd.DataFrame(
                {
                    LABELS.get(cat, cat): [counts.get(s, 0) for s in SEVERITIES]
                    for cat, counts in sev_by_cat.items()
                },
                index=SEVERITIES,
            )
            st.dataframe(df_matrix, use_container_width=True)

    # ========================================================
    # RQ2.3
    # ========================================================
    st.markdown("### RQ2.3: confronto con la metodologia classica")

    if not rq2_3.get("available"):
        st.warning(
            f"Confronto con la metodologia classica non disponibile: {rq2_3.get('error', 'errore sconosciuto')}"
        )
    else:
        b1, b2, b3, b4 = st.columns(4)
        b1.metric("Gruppo analizzato", rq2_3.get("target_total", 0))
        b2.metric(
            "Non caratterizzabili con la classica",
            f"{rq2_3.get('not_characterizable_classic', 0)} "
            f"({rq2_3.get('not_characterizable_classic_pct_of_target', 0)}%)",
            help="Assenti nello SBOM classico oppure presenti ma senza origine determinabile.",
        )
        b3.metric("Assenti nello SBOM classico", rq2_3.get("absent_in_classic_sbom", 0))
        b4.metric("Presenti ma senza origine", rq2_3.get("present_but_unresolved_in_classic", 0))

        st.caption(
            f"Caratterizzabili anche con la classica: {rq2_3.get('characterizable_classic', 0)} · "
            f"Non caratterizzabili sul totale dei vulnerabili: "
            f"{rq2_3.get('not_characterizable_classic_pct_of_all_vulnerable', 0)}%"
        )

        transitions = rq2_3.get("transitions", {})
        if transitions:
            rows = []
            for key, count in transitions.items():
                ours, classic = [p.strip() for p in key.split("->")]
                rows.append(
                    {
                        "Nostra metodologia": LABELS.get(ours, ours),
                        "Metodologia classica": LABELS.get(classic, classic),
                        "Componenti": count,
                    }
                )
            df_tr = pd.DataFrame(rows).sort_values("Componenti", ascending=False)
            with st.expander("Matrice di transizione (nostra → classica), tutti i vulnerabili"):
                st.dataframe(df_tr, use_container_width=True, hide_index=True)

    # ========================================================
    # TABELLA COMPONENTI
    # ========================================================
    st.markdown(f"### Dichiarati e sconosciuti diretti vulnerabili ({len(target)})")

    if target:
        df_target = pd.DataFrame(
            [
                {
                    "Nome": c.get("name"),
                    "Versione": c.get("version"),
                    "Categoria": c.get("classification_label"),
                    "Classica": LABELS.get(c.get("classic_classification"), c.get("classic_classification")),
                    "Severità max": c.get("max_severity"),
                    "N. CVE": c.get("cve_count", 0),
                    "CVE": ", ".join(c.get("cves", [])),
                    "PURL": c.get("purl"),
                    "File sorgente": c.get("source_file"),
                    "Versione dichiarata": c.get("declared_version"),
                }
                for c in target
            ]
        )

        f1, f2 = st.columns(2)
        with f1:
            cat_filter = st.multiselect(
                "Filtra per categoria",
                options=sorted(df_target["Categoria"].dropna().unique()),
                default=[],
                key="char_cat_filter",
            )
        with f2:
            sev_filter = st.multiselect(
                "Filtra per severità",
                options=SEVERITIES,
                default=[],
                key="char_sev_filter",
            )

        if cat_filter:
            df_target = df_target[df_target["Categoria"].isin(cat_filter)]
        if sev_filter:
            df_target = df_target[df_target["Severità max"].isin(sev_filter)]

        st.dataframe(df_target, use_container_width=True, hide_index=True)
    else:
        st.info("Nessun componente dichiarato o sconosciuto diretto vulnerabile.")

    st.download_button(
        label="Scarica risultati RQ2 (JSON)",
        data=json.dumps(results, indent=2, ensure_ascii=False),
        file_name="rq2_results.json",
        mime="application/json",
    )