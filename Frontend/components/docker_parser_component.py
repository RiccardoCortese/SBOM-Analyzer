import streamlit as st
import plotly.graph_objects as go


def render_docker_sbom_analysis(steps, diffs):

    st.title("Docker SBOM Evolution")

    # -------------------------
    # Stato selezione
    # -------------------------

    if "selected_step" not in st.session_state:
        st.session_state.selected_step = None
    

    # -------------------------
    # Preparazione dati grafico
    # -------------------------

    step_stats = []

    for diff in diffs:

        step_stats.append(
            {
                "step": diff["to"],
                "added": len(diff["diff"].get("added", [])),
                "removed": len(diff["diff"].get("removed", [])),
                "updated": len(diff["diff"].get("updated", []))
            }
        )

    # -------------------------
    # Timeline Dockerfile
    # -------------------------

    st.subheader("📌 Dockerfile Timeline")

    for step in steps:

        col1, col2, col3 = st.columns([1, 5, 1])

        with col1:
            st.markdown(f"### STEP {step['index']}")

        with col2:
            st.code(
                step["dockerfile_content"],
                language="dockerfile"
            )

        with col3:

            if st.button(
                "Dettagli",
                key=f"btn_{step['index']}"
            ):
                st.session_state.selected_step = step["index"]
                st.rerun()

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

        fig.update_layout(
            barmode="group",
            xaxis_title="Step",
            yaxis_title="Packages"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    # -------------------------
    # Dettaglio Step
    # -------------------------
    if st.session_state.selected_step is not None:

        selected = st.session_state.selected_step

        st.subheader(f"🔎 Step {selected} diff")


        # Lo step 0 è quello iniziale
        if selected == 0:
            st.info(
                "Lo step iniziale non ha differenze rispetto a uno step precedente."
            )
            return


        current_diff = None


        for d in diffs:

            if d["to"] == selected:
                current_diff = d["diff"]
                break


        if current_diff is None:

            st.warning(
                f"Nessun diff trovato per lo step {selected}"
            )

            st.write("Diff disponibili:")
            st.write(
                [
                    d["to"]
                    for d in diffs
                ]
            )

            return


        col1, col2, col3 = st.columns(3)


        with col1:

            st.success(
                f"➕ Added ({len(current_diff.get('added', []))})"
            )

            with st.container(height=300, border=True):
                for pkg in current_diff.get("added", []):
                    st.write(f"+ {pkg}")


        with col2:

            st.error(
                f"➖ Removed ({len(current_diff.get('removed', []))})"
            )

            with st.container(height=300, border=True):
                for pkg in current_diff.get("removed", []):
                    st.write(f"- {pkg}")


        with col3:

            st.warning(
                f"🔄 Updated ({len(current_diff.get('updated', []))})"
            )

            with st.container(height=300, border=True):
                for pkg in current_diff.get("updated", []):
                    st.write(f"≈ {pkg}")