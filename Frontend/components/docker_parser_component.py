import streamlit as st
import plotly.graph_objects as go


def render_docker_sbom_analysis(steps, diffs):

    st.subheader("Docker SBOM Evolution")

    # -------------------------
    # Stato selezione
    # -------------------------

    if "selected_step" not in st.session_state:
        st.session_state.selected_step = None
    

    # -------------------------
    # Preparazione dati grafico
    # -------------------------
    totals_by_step = {step["index"]: step.get("total_components", 0) for step in steps}
    
    step_stats = []

    for diff in diffs:
        step_idx = diff["to"]
        current_diff = diff["diff"]
        step_stats.append(
            {
                "step": step_idx,
                "added": len(current_diff.get("added", [])),
                "removed": len(current_diff.get("removed", [])),
                "updated": len(current_diff.get("updated", [])),
                "total": totals_by_step.get(step_idx, 0)
            }
        )
        
    # -------------------------
    # Timeline Dockerfile
    # -------------------------

    with st.expander("📌 Dockerfile Timeline" ):
    
        for step in steps:
            with st.expander(f"Step {step['index']}", expanded=False):
                
                col1, col2 = st.columns([1, 5])

                with col1:
                    st.markdown(f"### STEP {step['index']}")

                with col2:
                    st.code(
                        step["dockerfile_content"],
                        language="dockerfile"
                    )

                st.divider()

    # -------------------------
    # Grafico
    # -------------------------

    st.subheader("Cambiamenti per step")
    

    if len(step_stats) == 0:
        st.info("Nessuna differenza trovata.")
    else:

        fig = go.Figure()

        fig.add_bar(
            name="Added",
            x=[x["step"] for x in step_stats],
            y=[x["added"] for x in step_stats],
        )

        fig.add_bar(
            name="Removed",
            x=[x["step"] for x in step_stats],
            y=[x["removed"] for x in step_stats],
        )

        fig.add_bar(
            name="Updated",
            x=[x["step"] for x in step_stats],
            y=[x["updated"] for x in step_stats],
        )
        
        fig.add_scatter(
            name="Totale dipendenze",
            x=[x["step"] for x in step_stats],
            y=[x["total"] for x in step_stats],
            mode="lines+markers",
            yaxis="y2"
        )
        
        # Calcolo dinamico dei massimi basato sui dati reali dello step_stats
        max_value = max(
            [max(x["total"] ,x["added"], x["removed"], x["updated"]) for x in step_stats],
            default=10
        )

        fig.update_layout(
            barmode="group",
            xaxis_title="Step",
            yaxis=dict(
                title="Modifiche",
                range=[0, max_value * 1.1]
            ),
            yaxis2=dict(
                title="Dipendenze totali",
                overlaying="y",
                side="right",
                range=[0, max_value * 1.1]
            )
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    # -------------------------
    # Dettaglio Step
    # -------------------------
    
    selected_step  = st.selectbox(
        "Visualizza le modifiche dello step:",
        options=[step["index"] for step in steps],
        format_func=lambda x: f"Step {x}",
        key="selected_step"
    )
    
    if selected_step is not None:

        selected = selected_step

        st.subheader(f"🔎 Step {selected} diff")


        # Lo step 0 è quello iniziale
        if selected == 0:
            st.info("Lo step iniziale non ha differenze rispetto a uno step precedente.")
            return


        current_diff = None


        for d in diffs:

            if d["to"] == selected:
                current_diff = d["diff"]
                break


        if current_diff is None:

            st.warning(f"Nessun diff trovato per lo step {selected}")

            st.write("Diff disponibili:")
            st.write( [d["to"] for d in diffs]) # per ogni diff, mostra lo step di destinazione

            return


        col1, col2, col3 = st.columns(3)


        with col1:

            st.success(f"➕ Added ({len(current_diff.get('added', []))})")

            with st.container(height=300, border=True):
                for pkg in current_diff.get("added", []):
                    st.write(f"+ {pkg}")


        with col2:

            st.error(f"➖ Removed ({len(current_diff.get('removed', []))})")

            with st.container(height=300, border=True):
                for pkg in current_diff.get("removed", []):
                    st.write(f"- {pkg}")


        with col3:

            st.warning(f"🔄 Updated ({len(current_diff.get('updated', []))})")

            with st.container(height=300, border=True):
                for pkg in current_diff.get("updated", []):
                    st.write(f"≈ {pkg}")