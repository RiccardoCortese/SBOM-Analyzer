
import streamlit as st
import requests
import pandas as pd
import json
import requests


OURS = [
    "declared",
    "transitive",
    "unknown",
    "transitive_unknown",
    "unmapped",
]

CLASSIC = [
    "declared",
    "transitive",
    "unknown",
]

SEVERITIES = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "UNKNOWN",
]

LABELS = {
    "declared": "Dichiarato",
    "transitive": "Transitivo",
    "unknown": "Sconosciuto diretto",
    "transitive_unknown": "Sconosciuto transitivo",
    "unmapped": "Non presente nel grafo",
}

CLASSIC_LABELS = {
    "declared": "Dichiarato",
    "transitive": "Transitivo",
    "unknown": "Sconosciuto (non distinto)",
}

VARIANTS = {
    "Classica: solo manifest": "source_only",
    "Classica: manifest + immagine": "source_plus_image",
}


# ============================================================
# FUNZIONI DI SUPPORTO
# ============================================================

def _rq23_safe_dict(value):
    return value if isinstance(value, dict) else {}


def _rq23_safe_list(value):
    return value if isinstance(value, list) else []


def _rq23_dataframe_counts(
    counts,
    categories=OURS,
    labels=LABELS,
):
    counts = _rq23_safe_dict(counts)

    return pd.DataFrame([
        {
            "Categoria": labels.get(category, category),
            "Componenti": counts.get(category, 0),
        }
        for category in categories
    ])


def _rq23_render_vulnerability_table(
    components,
    classification_field="ours",
    classic_field=None,
    key_prefix="rq23",
):
    """Tabella filtrabile dei componenti vulnerabili restituiti dal backend."""

    components = _rq23_safe_list(components)

    if not components:
        st.info("Nessun componente vulnerabile disponibile.")
        return

    df = pd.DataFrame([
        {
            "Nome": c.get("name"),
            "Versione": c.get("version"),

            "Classificazione": (
                c.get("ours_label")
                or LABELS.get(
                    c.get(classification_field),
                    c.get(classification_field, "Non disponibile"),
                )
            ),

            "Solo manifest": LABELS.get(
                c.get("manifests_only"),
                c.get("manifests_only", "Non disponibile"),
            ),

            "Manifest + step": LABELS.get(
                c.get("manifests_steps"),
                c.get("manifests_steps", "Non disponibile"),
            ),

            "Classica": (
                CLASSIC_LABELS.get(
                    c.get(classic_field),
                    c.get(classic_field, "Non disponibile"),
                )
                if classic_field
                else None
            ),

            "Origine": (
                c.get("manifests_steps_origin")
                or c.get("origin")
            ),

            "Severità massima": c.get("max_severity"),
            "Numero CVE": c.get("cve_count", 0),
            "CVE": ", ".join(c.get("cves") or []),
            "PURL": c.get("purl"),
        }
        for c in components
        if isinstance(c, dict)
    ])

    if df.empty:
        st.info("Nessun dettaglio dei componenti disponibile.")
        return

    c1, c2 = st.columns(2)

    with c1:
        categories = sorted(
            df["Classificazione"].dropna().unique()
        )

        selected_categories = st.multiselect(
            "Filtra per classificazione",
            categories,
            key=f"{key_prefix}_categories",
        )

    with c2:
        selected_severities = st.multiselect(
            "Filtra per severità",
            SEVERITIES,
            key=f"{key_prefix}_severities",
        )

    if selected_categories:
        df = df[
            df["Classificazione"].isin(selected_categories)
        ]

    if selected_severities:
        df = df[
            df["Severità massima"].isin(selected_severities)
        ]

    st.caption(f"Componenti visualizzati: {len(df)}")

    st.dataframe(
        df,
        width="stretch",
        hide_index=True,
    )


def _rq23_render_variant(variant, key_prefix):
    """Mostra il confronto fra la classificazione proposta e una baseline classica."""

    if not isinstance(variant, dict):
        st.error("Formato della variante non valido.")
        return

    if not variant.get("available"):
        st.error(
            "Variante non disponibile: "
            f"{variant.get('error', 'errore sconosciuto')}"
        )
        return

    unknown = variant.get("classic_unknown_components", 0)
    unknown_vuln = variant.get("classic_unknown_vulnerable", 0)
    direct = variant.get("vulnerable_directly_actionable", 0)
    indirect = variant.get("vulnerable_indirect", 0)

    c1, c2, c3 = st.columns(3)

    c1.metric(
        "Sconosciuti per la classica",
        unknown,
    )

    c2.metric(
        "Di cui vulnerabili",
        unknown_vuln,
    )

    c3.metric(
        "Vulnerabili direttamente azionabili",
        f"{direct} ({variant.get('vulnerable_directly_actionable_pct', 0)}%)",
        help=(
            "Componenti vulnerabili classificati dalla metodologia proposta "
            "come dichiarati o sconosciuti diretti."
        ),
    )

    st.caption(
        f"Vulnerabili indiretti: {indirect}. "
        f"Radici distinte da cui derivano: "
        f"{variant.get('distinct_roots_for_indirect', 0)}. "
        f"Azioni stimate: {variant.get('estimated_actions', 0)}."
    )

    st.metric(
        "Sconosciuti riclassificati come dichiarati o transitivi",
        variant.get("recovered_as_declared_or_transitive", 0),
        help=(
            "Numero di componenti del gruppo sconosciuto classico "
            "che la metodologia proposta classifica come dichiarati "
            "o transitivi."
        ),
    )

    by_all = _rq23_safe_dict(
        variant.get("classic_unknown_by_ours")
    )

    by_vuln = _rq23_safe_dict(
        variant.get("classic_unknown_vulnerable_by_ours")
    )

    df_split = pd.DataFrame([
        {
            "Classificazione": LABELS[category],
            "Componenti": by_all.get(category, 0),
            "Vulnerabili": by_vuln.get(category, 0),
        }
        for category in OURS
    ])

    st.markdown("**Scomposizione del gruppo sconosciuto della classica**")

    left, right = st.columns(2)

    with left:
        st.dataframe(
            df_split,
            width="stretch",
            hide_index=True,
        )

    with right:
        st.bar_chart(
            df_split.set_index("Classificazione")[["Vulnerabili"]]
        )

    with st.expander("Matrice di confronto fra le classificazioni"):
        for title, matrix_key in (
            ("Componenti vulnerabili", "matrix_vulnerable"),
            ("Tutti i componenti", "matrix_all"),
        ):
            matrix = _rq23_safe_dict(
                variant.get(matrix_key)
            )

            df_matrix = pd.DataFrame(
                {
                    CLASSIC_LABELS[category]: [
                        (
                            matrix.get(ours, {}).get(category, 0)
                            if isinstance(matrix.get(ours, {}), dict)
                            else 0
                        )
                        for ours in OURS
                    ]
                    for category in CLASSIC
                },
                index=[LABELS[ours] for ours in OURS],
            )

            st.markdown(f"**{title}**")

            st.dataframe(
                df_matrix,
                width="stretch",
            )

    severity = _rq23_safe_dict(
        variant.get("severity_by_ours_category")
    )

    if severity:
        with st.expander(
            "Severità dei vulnerabili sconosciuti per categoria"
        ):
            df_severity = pd.DataFrame(
                {
                    sev: [
                        (
                            severity.get(ours, {}).get(sev, 0)
                            if isinstance(severity.get(ours, {}), dict)
                            else 0
                        )
                        for ours in OURS
                    ]
                    for sev in SEVERITIES
                },
                index=[LABELS[ours] for ours in OURS],
            )

            st.dataframe(
                df_severity,
                width="stretch",
            )


def _rq23_render_scenario_comparison(image):
    """
    Mostra il confronto fra:
      A. solo manifest;
      B. manifest + step Docker.

    I dati sono letti da image.characterization_comparison,
    prodotto dalla nuova rotta backend.
    """

    image = _rq23_safe_dict(image)

    comparison = _rq23_safe_dict(
        image.get("characterization_comparison")
    )

    # Fallback per risposte backend che contengono i conteggi
    # nei campi classification_counts, ma non il nuovo riepilogo.
    classification_counts = _rq23_safe_dict(
        image.get("classification_counts")
    )

    if not comparison:
        counts_a = _rq23_safe_dict(
            classification_counts.get("manifests_only")
        )

        counts_b = _rq23_safe_dict(
            classification_counts.get("manifests_steps")
        )

        if not counts_a:
            counts_a = _rq23_safe_dict(
                classification_counts.get("source_only")
            )

        if not counts_b:
            counts_b = _rq23_safe_dict(
                classification_counts.get("ours")
            )

        universe = image.get("components", 0)

        def count_classified(counts):
            return sum(
                counts.get(category, 0)
                for category in (
                    "declared",
                    "transitive",
                    "unknown",
                    "transitive_unknown",
                )
            )

        classified_a = count_classified(counts_a)
        classified_b = count_classified(counts_b)

        comparison = {
            "universe_components": universe,
            "manifests_only": {
                "counts": counts_a,
                "classified_components": classified_a,
                "classified_pct": (
                    round(classified_a / universe * 100, 2)
                    if universe
                    else 0
                ),
                "unmapped_components": counts_a.get("unmapped", 0),
            },
            "manifests_steps": {
                "counts": counts_b,
                "classified_components": classified_b,
                "classified_pct": (
                    round(classified_b / universe * 100, 2)
                    if universe
                    else 0
                ),
                "unmapped_components": counts_b.get("unmapped", 0),
            },
            "additional_classified_components": classified_b - classified_a,
        }

    scenario_a = _rq23_safe_dict(
        comparison.get("manifests_only")
    )

    scenario_b = _rq23_safe_dict(
        comparison.get("manifests_steps")
    )

    counts_a = _rq23_safe_dict(
        scenario_a.get("counts")
    )

    counts_b = _rq23_safe_dict(
        scenario_b.get("counts")
    )

    universe = comparison.get(
        "universe_components",
        image.get("components", 0),
    )

    classified_a = scenario_a.get(
        "classified_components",
        sum(
            counts_a.get(c, 0)
            for c in (
                "declared",
                "transitive",
                "unknown",
                "transitive_unknown",
            )
        ),
    )

    classified_b = scenario_b.get(
        "classified_components",
        sum(
            counts_b.get(c, 0)
            for c in (
                "declared",
                "transitive",
                "unknown",
                "transitive_unknown",
            )
        ),
    )

    pct_a = scenario_a.get(
        "classified_pct",
        round(classified_a / universe * 100, 2) if universe else 0,
    )

    pct_b = scenario_b.get(
        "classified_pct",
        round(classified_b / universe * 100, 2) if universe else 0,
    )

    unmapped_a = scenario_a.get(
        "unmapped_components",
        counts_a.get("unmapped", 0),
    )

    unmapped_b = scenario_b.get(
        "unmapped_components",
        counts_b.get("unmapped", 0),
    )

    additional = comparison.get(
        "additional_classified_components",
        classified_b - classified_a,
    )

    pct_points = comparison.get(
        "additional_classified_pct_points",
        round(pct_b - pct_a, 2),
    )

    st.markdown("### Confronto diretto delle caratterizzazioni")

    st.info(
        "Entrambi gli scenari classificano lo stesso universo di componenti, "
        "derivato da docker_sbom.json. Lo SBOM dell'immagine non contribuisce "
        "alle relazioni dei grafi usati in questo confronto."
    )

    st.caption(
        f"Universo comune: {universe} componenti."
    )

    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("**Scenario A — Solo manifest**")

        st.metric(
            "Componenti classificati",
            f"{classified_a} / {universe}",
            f"{pct_a}% dell'universo",
        )

        st.metric(
            "Non presenti nel grafo",
            unmapped_a,
        )

    with col_b:
        st.markdown("**Scenario B — Manifest + step Docker**")

        st.metric(
            "Componenti classificati",
            f"{classified_b} / {universe}",
            f"{pct_b}% dell'universo",
        )

        st.metric(
            "Non presenti nel grafo",
            unmapped_b,
        )

    st.markdown("**Differenza tra gli scenari**")

    d1, d2 = st.columns(2)

    d1.metric(
        "Componenti classificati in più",
        additional,
        help=(
            "Differenza tra i componenti classificati nello scenario B "
            "e quelli classificati nello scenario A. Un valore negativo "
            "indica che lo scenario B ne classifica meno."
        ),
    )

    d2.metric(
        "Variazione della copertura",
        f"{pct_points:+.2f} punti percentuali",
    )

    if additional > 0:
        st.success(
            f"Aggiungendo gli step Docker vengono classificati "
            f"{additional} componenti in più rispetto ai soli manifest."
        )
    elif additional < 0:
        st.warning(
            f"Con manifest + step risultano classificati "
            f"{abs(additional)} componenti in meno rispetto ai soli manifest. "
            "L'aggiunta di relazioni può modificare la classificazione "
            "dei componenti."
        )
    else:
        st.info(
            "Il numero complessivo di componenti classificati è uguale "
            "nei due scenari. Le singole categorie potrebbero comunque "
            "essere diverse."
        )

    # --------------------------------------------------------
    # Distribuzione delle categorie nei due scenari
    # --------------------------------------------------------

    df_counts = pd.DataFrame({
        "Categoria": [LABELS[c] for c in OURS],
        "Solo manifest": [
            counts_a.get(c, 0)
            for c in OURS
        ],
        "Manifest + step Docker": [
            counts_b.get(c, 0)
            for c in OURS
        ],
    })

    st.markdown("**Distribuzione completa delle categorie**")

    st.dataframe(
        df_counts,
        width="stretch",
        hide_index=True,
    )

    st.bar_chart(
        df_counts.set_index("Categoria"),
        horizontal=True,
    )

    # --------------------------------------------------------
    # Differenza per categoria
    # --------------------------------------------------------

    df_delta = pd.DataFrame([
        {
            "Categoria": LABELS[category],
            "Solo manifest": counts_a.get(category, 0),
            "Manifest + step Docker": counts_b.get(category, 0),
            "Differenza": (
                counts_b.get(category, 0)
                - counts_a.get(category, 0)
            ),
        }
        for category in OURS
    ])

    with st.expander("Differenza per singola categoria"):
        st.dataframe(
            df_delta,
            width="stretch",
            hide_index=True,
        )

    # --------------------------------------------------------
    # Dettagli: vulnerabilità per scenario
    # --------------------------------------------------------

    st.caption(
        "Il confronto precedente riguarda tutti i componenti dell'universo. "
        "La tabella seguente, invece, riguarda esclusivamente i componenti "
        "vulnerabili e mostra la categoria assegnata da ciascuno scenario."
    )



def _rq23_render_newly_characterized_components(components):
    """
    Mostra tutti i componenti che:
    - nella prima analisi sono unmapped;
    - nella seconda analisi sono caratterizzati.
    
    Include anche componenti senza vulnerabilità.
    """

    components = _rq23_safe_list(components)

    st.markdown(
        "### Componenti recuperati grazie agli step Docker"
    )

    st.caption(
        "Sono mostrati i componenti che risultano non presenti nel grafo "
        "usando solo i manifest, ma che vengono caratterizzati usando "
        "manifest e SBOM degli step Docker."
    )

    if not components:
        st.info(
            "Nessun componente aggiuntivo caratterizzato. "
            "Verifica che il backend restituisca "
            "'newly_characterized_components'."
        )
        return

    df = pd.DataFrame([
        {
            "Nome": component.get("name"),
            "Versione": component.get("version"),
            "PURL": component.get("purl"),
            "Prima analisi": LABELS.get(
                component.get("manifests_only"),
                component.get("manifests_only", "Non disponibile"),
            ),
            "Seconda analisi": LABELS.get(
                component.get("manifests_steps"),
                component.get("manifests_steps", "Non disponibile"),
            ),
            "Origine": (
                component.get("manifests_steps_origin")
                or component.get("origin")
            ),
            "Severità massima": component.get("max_severity"),
            "Numero CVE": component.get("cve_count", 0),
            "CVE": ", ".join(component.get("cves") or []),
        }
        for component in components
        if isinstance(component, dict)
        and component.get("manifests_only") == "unmapped"
        and component.get("manifests_steps") in {
            "declared",
            "transitive",
            "unknown",
            "transitive_unknown",
        }
    ])

    if df.empty:
        st.info(
            "Nessun componente soddisfa i criteri del confronto."
        )
        return

    st.metric(
        "Componenti aggiuntivi caratterizzati",
        len(df),
    )

    # Filtro per la categoria assegnata dalla seconda analisi.
    categories = df["Seconda analisi"].dropna().unique().tolist()

    selected_categories = st.multiselect(
        "Filtra per classificazione della seconda analisi",
        options=categories,
        default=categories,
        key="rq23_new_components_categories",
    )

    filtered_df = df[
        df["Seconda analisi"].isin(selected_categories)
    ]

    st.caption(
        f"Componenti visualizzati: {len(filtered_df)} su {len(df)}."
    )

    st.dataframe(
        filtered_df,
        width="stretch",
        hide_index=True,
    )

    st.download_button(
        label="Scarica i componenti aggiuntivi in CSV",
        data=filtered_df.to_csv(index=False).encode("utf-8"),
        file_name="rq2_3_newly_characterized_components.csv",
        mime="text/csv",
        key="rq23_new_components_download",
        width="stretch",
    )


def _rq23_render_depsdev_comparison(results):
    """Confronto tra manifest + step e manifest + step + deps.dev."""

    results = _rq23_safe_dict(results)
    image = _rq23_safe_dict(results.get("image"))
    comparison = _rq23_safe_dict(
        image.get("characterization_comparison")
    )
    depsdev = _rq23_safe_dict(results.get("depsdev"))
    stats = _rq23_safe_dict(depsdev.get("stats"))

    scenario_b = _rq23_safe_dict(
        comparison.get("manifests_steps")
    )
    scenario_c = _rq23_safe_dict(
        comparison.get("manifests_steps_depsdev")
    )

    if not scenario_c:
        st.warning(
            "Il backend non ha restituito il confronto con deps.dev. "
            "Verifica che la nuova caratterizzazione sia stata aggiunta "
            "alla rotta RQ2.3."
        )
        return

    counts_b = _rq23_safe_dict(scenario_b.get("counts"))
    counts_c = _rq23_safe_dict(scenario_c.get("counts"))

    classified_b = scenario_b.get("classified_components", 0)
    classified_c = scenario_c.get("classified_components", 0)
    universe = comparison.get("universe_components", 0)

    additional = classified_c - classified_b
    pct_b = scenario_b.get("classified_pct", 0)
    pct_c = scenario_c.get("classified_pct", 0)

    recovered = _rq23_safe_list(
        depsdev.get("recovered_components")
    )
    reclassified = _rq23_safe_list(
        depsdev.get("reclassified_components")
    )
    vulnerable = _rq23_safe_list(
        depsdev.get("vulnerable_reclassified_components")
    )
    added_edges = _rq23_safe_list(
        depsdev.get("added_edges")
    )

    st.markdown("### Contributo delle relazioni deps.dev")

    st.caption(
        "Il confronto mantiene invariato l'insieme dei componenti "
        "dell'immagine finale. Cambiano soltanto le relazioni utilizzate "
        "per caratterizzarli."
    )

    col_b, col_c = st.columns(2)

    with col_b:
        st.markdown("**B — Manifest + step Docker**")
        st.metric(
            "Componenti classificati",
            f"{classified_b} / {universe}",
            f"{pct_b:.2f}% dell'universo",
        )
        st.metric(
            "Non presenti nel grafo",
            counts_b.get("unmapped", 0),
        )

    with col_c:
        st.markdown("**C — Manifest + step + deps.dev**")
        st.metric(
            "Componenti classificati",
            f"{classified_c} / {universe}",
            f"{pct_c:.2f}% dell'universo",
        )
        st.metric(
            "Non presenti nel grafo",
            counts_c.get("unmapped", 0),
        )

    m1, m2, m3 = st.columns(3)

    m1.metric(
        "Componenti classificati in più",
        f"{additional:+}",
        f"{pct_c - pct_b:+.2f} punti percentuali",
    )
    m2.metric(
        "Componenti riclassificati",
        len(reclassified),
    )
    m3.metric(
        "Archi aggiunti da deps.dev",
        len(added_edges),
    )

    st.caption(
        f"Query supportate effettuate: "
        f"{stats.get('supported_components_queried', 0)}. "
        f"Errori API: {stats.get('api_errors', 0)}."
    )

    if stats.get("api_errors", 0):
        with st.expander("Dettaglio degli errori deps.dev"):
            st.dataframe(
                pd.DataFrame(stats.get("errors", [])),
                width="stretch",
                hide_index=True,
            )

    # Confronto delle categorie nei due scenari.
    df_counts = pd.DataFrame([
        {
            "Categoria": LABELS[category],
            "Manifest + step": counts_b.get(category, 0),
            "Con deps.dev": counts_c.get(category, 0),
            "Differenza": (
                counts_c.get(category, 0)
                - counts_b.get(category, 0)
            ),
        }
        for category in OURS
    ])

    st.markdown("**Come cambia la distribuzione delle categorie**")
    st.dataframe(
        df_counts,
        width="stretch",
        hide_index=True,
    )

    # Componenti che erano sconosciuti o unmapped e cambiano categoria.
    st.markdown("**Componenti riclassificati grazie alle nuove relazioni**")

    if reclassified:
        df_reclassified = pd.DataFrame([
            {
                "Componente": c.get("name"),
                "Versione": c.get("version"),
                "Prima": LABELS.get(
                    c.get("before"), c.get("before")
                ),
                "Dopo": LABELS.get(
                    c.get("after"), c.get("after")
                ),
                "Vulnerabile": c.get("vulnerable", False),
                "Severità": c.get("max_severity") or "-",
                "Numero CVE": c.get("cve_count", 0),
                "PURL": c.get("purl"),
            }
            for c in reclassified
        ])

        st.dataframe(
            df_reclassified,
            width="stretch",
            hide_index=True,
        )

        st.download_button(
            "Scarica componenti riclassificati (CSV)",
            data=df_reclassified.to_csv(index=False).encode("utf-8"),
            file_name="rq2_3_depsdev_reclassified.csv",
            mime="text/csv",
            key="rq23_depsdev_reclassified_download",
            width="stretch",
        )
    else:
        st.info(
            "Nessun componente sconosciuto o non presente nel grafo "
            "ha cambiato categoria con le relazioni recuperate."
        )

    st.caption(
        f"Tra i componenti riclassificati, {len(recovered)} "
        "sono diventati dichiarati o transitivi; "
        f"{len(vulnerable)} presentano vulnerabilità."
    )

    # Dettaglio degli archi aggiunti dall'API.
    with st.expander(
        f"Relazioni aggiunte da deps.dev ({len(added_edges)})"
    ):
        if added_edges:
            df_edges = pd.DataFrame([
                {
                    "Componente padre": edge.get("source_name"),
                    "Versione padre": edge.get("source_version"),
                    "Dipendenza": edge.get("target_name"),
                    "Versione dipendenza": edge.get("target_version"),
                    "PURL padre": edge.get("source_purl"),
                    "PURL dipendenza": edge.get("target_purl"),
                    "Origine": edge.get("origin", "deps.dev"),
                }
                for edge in added_edges
            ])

            st.dataframe(
                df_edges,
                width="stretch",
                hide_index=True,
            )
        else:
            st.info(
                "Nessun nuovo arco compatibile con i componenti "
                "presenti nell'immagine."
            )


# ============================================================
# PAGINA RQ2.3
# ============================================================

def render_rq2_3_analysis(backend_url: str):
    st.subheader(
        "RQ2.3: caratterizzazione dei componenti sconosciuti"
    )

    st.info(
        "L'analisi confronta due scenari di caratterizzazione degli stessi "
        "componenti dell'immagine Docker: il primo utilizza esclusivamente "
        "gli SBOM dei manifest; il secondo utilizza gli SBOM dei manifest "
        "e degli step del Dockerfile. Lo SBOM dell'immagine finale definisce "
        "l'universo da analizzare, ma non viene usato per costruire i grafi "
        "dei due scenari. Le vulnerabilità dell'immagine provengono dal "
        "report CycloneDX dell'immagine; i componenti degli SBOM sorgente "
        "sono sottoposti a una scansione Trivy separata."
    )

    # --------------------------------------------------------
    # Opzioni della rotta
    # --------------------------------------------------------

    with st.expander(
        "Opzioni dell'analisi",
        expanded=False,
    ):
        exclude_first_party = st.checkbox(
            "Escludi i componenti di prima parte",
            value=False,
            key="rq23_exclude_first_party",
            help=(
                "Esclude i componenti il cui namespace corrisponde ai gruppi "
                "dei componenti radice degli SBOM sorgente."
            ),
        )

        libraries_only = st.checkbox(
            "Considera solo le librerie",
            value=True,
            key="rq23_libraries_only",
            help=(
                "Esclude i pacchetti OS con PURL pkg:deb, pkg:apk e pkg:rpm."
            ),
        )

        include_removed = st.checkbox(
            "Includi i componenti rimossi negli step",
            value=False,
            key="rq23_include_removed",
            help=(
                "Se attivo, i componenti rimossi possono contribuire al grafo "
                "degli step. L'universo da analizzare rimane quello "
                "dell'immagine finale."
            ),
        )

    if st.button(
        "Analizza RQ2.3",
        width="stretch",
    ):
        params = {
            "exclude_first_party": exclude_first_party,
            "libraries_only": libraries_only,
            "include_removed": include_removed,
        }

        with st.spinner("Analisi in corso..."):
            try:
                res = requests.get(
                    f"{backend_url.rstrip('/')}/rq2-3-analysis",
                    params=params,
                    timeout=900,
                )

                if res.status_code == 200:
                    response_data = res.json()

                    if not isinstance(response_data, dict):
                        st.error(
                            "La risposta del backend non è un oggetto JSON."
                        )
                    elif response_data.get("status") != "success":
                        st.error(
                            response_data.get(
                                "message",
                                "Il backend non ha completato l'analisi.",
                            )
                        )
                    else:
                        st.session_state.rq23_results = response_data
                        st.success("Analisi completata!")
                        st.rerun()

                else:
                    try:
                        error_data = res.json()

                        detail = (
                            error_data.get(
                                "detail",
                                "Errore sconosciuto",
                            )
                            if isinstance(error_data, dict)
                            else error_data
                        )

                    except (ValueError, AttributeError):
                        detail = res.text or "Errore sconosciuto"

                    st.error(
                        f"Analisi fallita: {detail}"
                    )

            except requests.RequestException as e:
                st.error(
                    f"Errore di connessione: {e}"
                )

            except ValueError as e:
                st.error(
                    f"La risposta del backend non è JSON valido: {e}"
                )

    results = st.session_state.get("rq23_results")

    if not isinstance(results, dict) or not results:
        return

    if results.get("status") not in (None, "success"):
        st.error(
            results.get("message", "Risultati non validi.")
        )
        return

    options = _rq23_safe_dict(
        results.get("options")
    )

    st.caption(
        "Configurazione dei risultati: "
        f"solo librerie = {options.get('libraries_only', True)}; "
        f"esclusione prima parte = {options.get('exclude_first_party', False)}; "
        f"inclusione rimossi = {options.get('include_removed', False)}."
    )

    # ========================================================
    # 1. GRAFI
    # ========================================================

    st.markdown("## 1. Informazioni sui grafi")

    graph = _rq23_safe_dict(
        results.get("graph")
    )

    graph_rows = []

    for key, label in (
        ("image", "Immagine finale"),
        ("manifests", "Manifest"),
        ("steps", "Step Dockerfile"),
        ("union", "Unione dei grafi"),
    ):
        data = _rq23_safe_dict(
            graph.get(key)
        )

        graph_rows.append({
            "Grafo": label,
            "Componenti unici": data.get("components", 0),
            "Relazioni": data.get("relations", 0),
            "Componenti dell'immagine con genitore": data.get(
                "universe_with_parent",
                0,
            ),
            "Componenti dell'immagine con figli": data.get(
                "universe_with_children",
                0,
            ),
        })

    st.dataframe(
        pd.DataFrame(graph_rows),
        width="stretch",
        hide_index=True,
    )

    g1, g2, g3 = st.columns(3)

    g1.metric(
        "Relazioni nuove dagli step",
        graph.get("relations_new_from_steps", 0),
    )

    g2.metric(
        "Relazioni nuove dall'immagine",
        graph.get("relations_new_from_image", 0),
    )

    g3.metric(
        "Relazioni nuove dai manifest",
        graph.get("relations_new_from_manifests", 0),
    )

    image_graph = _rq23_safe_dict(
        graph.get("image")
    )

    if image_graph.get("flat"):
        st.warning(
            "Lo SBOM dell'immagine non contiene relazioni tra componenti. "
            "I due scenari di confronto usano quindi le relazioni recuperabili "
            "dai manifest e dagli step Docker."
        )

    steps_graph = _rq23_safe_dict(
        graph.get("steps")
    )

    st.caption(
        f"File SBOM degli step analizzati: "
        f"{steps_graph.get('files', 0)}."
    )

    st.divider()

    # ========================================================
    # 2. ANALISI COMPONENTI SORGENTE
    # ========================================================

    st.markdown(
        "## 2. Analisi dei componenti degli SBOM sorgente"
    )

    source = _rq23_safe_dict(
        results.get("source")
    )

    if not source.get("classification_available", False):
        st.warning(
            "Caratterizzazione dello SBOM sorgente non disponibile: "
            f"{source.get('classification_error', 'errore sconosciuto')}"
        )

    source_counts = _rq23_safe_dict(
        source.get("classification_counts_source_only")
    )

    source_ours_counts = _rq23_safe_dict(
        source.get("classification_counts_ours")
    )

    source_vulnerable_components = _rq23_safe_list(
        source.get("vulnerable_components")
    )

    # Il backend corrente restituisce vulnerable_components come lista.
    # Non bisogna confondere la lista con un contatore.
    source_vulnerable_count = len(
        source_vulnerable_components
    )

    sc1, sc2, sc3 = st.columns(3)

    sc1.metric(
        "Componenti sorgente",
        source.get("components", 0),
    )

    sc2.metric(
        "Componenti vulnerabili nella scansione sorgente",
        source.get(
            "vulnerable_components",
            source.get("vulnerable_components_count", source_vulnerable_count),
        )
        if isinstance(source.get("vulnerable_components"), (int, float))
        else source_vulnerable_count,
    )

    sc3.metric(
        "Componenti esclusi come prima parte",
        source.get("first_party_excluded", 0),
    )

    sv = _rq23_safe_dict(
        source.get("vulnerability_scan")
    )

    st.caption(
        f"Scansionati con Trivy: {sv.get('scanned', 0)}. "
        f"Senza PURL o versione: {sv.get('no_version_or_purl', 0)}. "
        f"Pacchetti OS esclusi: {sv.get('skipped_os_packages', 0)}."
    )

    if sv.get("error"):
        st.warning(
            f"Scansione vulnerabilità sorgente: {sv['error']}"
        )

    if source.get("classification_available", False):
        left, right = st.columns(2)

        with left:
            st.markdown(
                "**Classificazione classica: solo manifest**"
            )

            st.dataframe(
                _rq23_dataframe_counts(
                    source_counts,
                ),
                width="stretch",
                hide_index=True,
            )

        with right:
            st.markdown(
                "**Classificazione con il grafo aggregato**"
            )

            st.dataframe(
                _rq23_dataframe_counts(
                    source_ours_counts,
                ),
                width="stretch",
                hide_index=True,
            )

        variants_source = _rq23_safe_dict(
            source.get("variants")
        )

        with st.expander(
            "Confronto classico sullo SBOM sorgente"
        ):
            _rq23_render_variant(
                variants_source.get("source_only", {}),
                "rq23_source_variant",
            )

    st.markdown(
        "### Componenti sorgente vulnerabili"
    )

    st.caption(
        "Questa tabella contiene i componenti vulnerabili restituiti "
        "dalla scansione Trivy separata degli SBOM sorgente."
    )

    _rq23_render_vulnerability_table(
        source_vulnerable_components,
        classification_field="ours",
        classic_field="classic_source_only",
        key_prefix="rq23_source",
    )

    st.divider()

    # ========================================================
    # 3. COMPONENTI DELL'IMMAGINE
    # ========================================================

    st.markdown(
        "## 3. Analisi dei componenti dell'immagine Docker"
    )

    image = _rq23_safe_dict(
        results.get("image")
    )

    i1, i2, i3 = st.columns(3)

    i1.metric(
        "Componenti nell'immagine",
        image.get("components", 0),
    )

    i2.metric(
        "Componenti vulnerabili",
        image.get("vulnerable_components", 0),
    )

    i3.metric(
        "Componenti non presenti nel grafo",
        image.get("not_in_graph", 0),
    )

    if image.get("not_in_graph", 0):
        st.warning(
            f"{image.get('not_in_graph', 0)} componenti dell'immagine "
            f"({image.get('not_in_graph_vulnerable', 0)} vulnerabili) "
            "non risultano classificati dalla caratterizzazione principale."
        )

    if image.get("os_excluded", 0):
        st.caption(
            "Pacchetti OS esclusi dall'universo di analisi: "
            f"{image.get('os_excluded', 0)}."
        )

    if image.get("first_party_excluded", 0):
        st.caption(
            "Componenti dell'immagine esclusi come prima parte: "
            f"{image.get('first_party_excluded', 0)}."
        )

    # ========================================================
    # 4. NUOVO CONFRONTO: SOLO MANIFEST VS MANIFEST + STEP
    # ========================================================

    st.markdown("## 4. Confronto tra i due scenari di caratterizzazione")

    _rq23_render_scenario_comparison(image)
    
    # Confronto B -> C: effetto delle relazioni deps.dev.
    _rq23_render_depsdev_comparison(results)
    
    # ========================================================
    # 4.1 COMPONENTI AGGIUNTIVI CARATTERIZZATI
    # ========================================================

    st.divider()

    newly_characterized = _rq23_safe_list(
        results.get("newly_characterized_components")
    )

    _rq23_render_newly_characterized_components(
        newly_characterized
    )

    # ========================================================
    # 5. BASELINE CLASSICA
    # ========================================================

    st.divider()

    st.markdown(
        "## 5. Confronto con la metodologia classica"
    )

    variants = _rq23_safe_dict(
        results.get("variants")
    )

    choice = st.radio(
        "Baseline da confrontare",
        list(VARIANTS.keys()),
        horizontal=True,
        key="rq23_variant",
    )

    variant = variants.get(
        VARIANTS[choice],
        {},
    )

    _rq23_render_variant(
        variant,
        f"rq23_image_{VARIANTS[choice]}",
    )

    # ========================================================
    # 6. COMPONENTI VULNERABILI DELL'IMMAGINE
    # ========================================================

    st.divider()

    components = _rq23_safe_list(
        results.get("vulnerable_components")
    )

    st.markdown(
        f"## 6. Componenti vulnerabili dell'immagine ({len(components)})"
    )

    st.caption(
        "Per ciascun componente sono mostrate la classificazione "
        "con i soli manifest e quella con manifest + step Docker, "
        "quando i campi sono disponibili nella risposta del backend."
    )

    _rq23_render_vulnerability_table(
        components,
        classification_field="ours",
        classic_field="classic_" + VARIANTS[choice],
        key_prefix="rq23_image",
    )

    # ========================================================
    # 7. DOWNLOAD RISULTATI
    # ========================================================

    st.divider()

    st.download_button(
        label="Scarica risultati RQ2.3 (JSON)",
        data=json.dumps(
            results,
            indent=2,
            ensure_ascii=False,
            default=str,
        ),
        file_name="rq2_3_results.json",
        mime="application/json",
        width="stretch",
    )
