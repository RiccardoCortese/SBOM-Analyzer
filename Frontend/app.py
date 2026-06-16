import streamlit as st
import requests
import pandas as pd
import json

st.set_page_config(page_title="TLSAssistant Flow", layout="wide")
st.title("🛡️ TLSAssistant - SBOM Analyzer")

BACKEND_URL = "http://127.0.0.1:8000"

# Inizializzazione Stati Permanenti di Streamlit
if "sbom_ready" not in st.session_state:
    st.session_state.sbom_ready = False
if "saved_repo" not in st.session_state:
    st.session_state.saved_repo = ""
if "saved_branch" not in st.session_state:
    st.session_state.saved_branch = "main"
if "saved_format" not in st.session_state:
    st.session_state.saved_format = "entrambi"
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = None
if "deep_sbom_results" not in st.session_state:
    st.session_state.deep_sbom_results = None

# ============================================================
# STEP 1: CONFIGURAZIONE TARGET & SBOM DI BASE
# ============================================================
st.subheader("1. Configurazione Target & SBOM di Base")

repo_url = st.text_input("GitHub Repository URL", value=st.session_state.saved_repo, placeholder="https://github.com/owner/repo")
branch = st.text_input("Branch", value=st.session_state.saved_branch)

sbom_choice = st.radio(
    "Scegli l'origine dello SBOM di base:",
    ["Genera SBOM Statico da zero", "Carica file SBOM esistenti"],
    horizontal=True
)

requirements_file = None
poetry_file = None

if sbom_choice == "Carica file SBOM esistenti":
    col1, col2 = st.columns(2)
    with col1:
        requirements_file = st.file_uploader("Carica JSON Requirements", type=["json"])
    with col2:
        poetry_file = st.file_uploader("Carica JSON Poetry", type=["json"])
elif sbom_choice == "Genera SBOM Statico da zero":
    format_type = st.selectbox(
        "Seleziona il formato da generare tramite la pipeline:",
        options=["entrambi", "requirements", "poetry"],
        format_func=lambda x: x.capitalize()
    )
    st.session_state.saved_format = format_type

if st.button("🔄 Invia e Mantieni in Memoria sul Server"):
    if not repo_url:
        st.error("Inserisci la URL della repo.")
        st.stop()
        
    st.session_state.saved_repo = repo_url
    st.session_state.saved_branch = branch

    with st.spinner("Salvataggio file sul server..."):
        try:
            if sbom_choice == "Genera SBOM Statico da zero":
                res = requests.post(f"{BACKEND_URL}/upload-sbom", data={"action": "generate"})
            else:
                files = {}
                if requirements_file: files["requirements_file"] = requirements_file.getvalue()
                if poetry_file: files["poetry_file"] = poetry_file.getvalue()
                res = requests.post(f"{BACKEND_URL}/upload-sbom", data={"action": "upload"}, files=files)
                
            if res.status_code == 200:
                st.session_state.sbom_ready = True
                st.success(res.json().get("message"))
                st.rerun()
            else:
                st.error(f"Errore server: {res.text}")
        except Exception as e:
            st.error(f"Errore di connessione: {str(e)}")

st.markdown("---")

# ============================================================
# STEP 2: ANALISI COMPARATIVA DINAMICA & DEEP INSPECTION
# ============================================================
if st.session_state.sbom_ready:
    st.subheader("2. Analisi Comparativa Dinamica")

    path_dipendenze = st.text_input(
        "Nome del file delle dipendenze dinamiche nella repo:",
        value="dependencies.json"
    ).strip()

    # Layout a due colonne per i pulsanti di attivazione delle pipeline
    btn_col1, btn_col2 = st.columns(2)

    with btn_col1:
        if st.button("📊 Genera Tabella di Confronto Base", use_container_width=True):
            with st.spinner("Innesco pipeline e calcolo matrice in corso..."):
                try:
                    res = requests.post(
                        f"{BACKEND_URL}/compare-dependencies",
                        params={
                            "repo_url": st.session_state.saved_repo,
                            "branch": st.session_state.saved_branch,
                            "path_dipendenze": path_dipendenze,
                            "format": st.session_state.saved_format,
                        },
                    )
                    if res.status_code == 200:
                        st.session_state.analysis_results = res.json()
                        st.success("Tabella di confronto generata!")
                    else:
                        st.error(f"Errore dal server FastAPI: {res.text}")
                        st.session_state.analysis_results = None
                except Exception as e:
                    st.error(f"Errore durante l'elaborazione: {str(e)}")
                    st.session_state.analysis_results = None

    with btn_col2:
        # QUESTO È IL BOTTONE CHE ATTIVA IL NUOVO ENDPOINT SUL BACKEND!
        if st.button("🔍 Avvia Deep Inspection (Genera SBOM Dipendenze)", use_container_width=True):
            with st.spinner("Avvio Job Matrix su GitHub. Trivy sta analizzando ogni singola sottodipendenza..."):
                try:
                    res = requests.post(
                        f"{BACKEND_URL}/analyze-dependencies-sbom",
                        params={
                            "repo_url": st.session_state.saved_repo,
                            "branch": st.session_state.saved_branch,
                            "path_dipendenze": path_dipendenze,
                        },
                    )
                    if res.status_code == 200:
                        st.session_state.deep_sbom_results = res.json()
                        st.success("Deep Inspection completata! Ora puoi scaricare gli SBOM riga per riga.")
                    else:
                        st.error(f"Errore dal server: {res.text}")
                        st.session_state.deep_sbom_results = None
                except Exception as e:
                    st.error(f"Errore di connessione: {str(e)}")
                    st.session_state.deep_sbom_results = None

    # RENDERING DEI RISULTATI
    if st.session_state.analysis_results is not None:
        result = st.session_state.analysis_results
        dependencies = result.get("result", [])
        git_repos = [item["url"] for item in dependencies if item.get("url") and "github.com" in item["url"]]
        comparison_report = result.get("comparison_matrix", None)
        raw_req = result.get("raw_requirements", None)
        raw_poe = result.get("raw_poetry", None)

        st.markdown("---")
        st.subheader("📊 Risultati dell'Analisi")

        # Configurazione Tab dinamici
        tab_labels = [f"📦 Componenti Rilevati ({len(dependencies)})", "🔗 Link GitHub Sorgenti"]
        if comparison_report: tab_labels.append("🔍 Matrice di Confronto (Pipeline)")
        if raw_req: tab_labels.append("📋 Trivy Requirements JSON")
        if raw_poe: tab_labels.append("📋 Trivy Poetry JSON")
        tab_labels.append("📄 JSON Grezzo Backend")

        tabs = st.tabs(tab_labels)

        # Tab 0: Tabella Componenti con bottoni di download riga per riga
        with tabs[0]:
            if dependencies:
                col_tipo, col_comp, col_sorg, col_req, col_poe, col_az = st.columns([1, 2, 3, 1.5, 1.5, 1.5])
                with col_tipo: st.markdown("**Tipo**")
                with col_comp: st.markdown("**Componente**")
                with col_sorg: st.markdown("**Sorgente / PURL**")
                with col_req:  st.markdown("**In Requirements**")
                with col_poe:  st.markdown("**In Poetry**")
                with col_az:   st.markdown("**Azione**")
                st.markdown("---")

                for idx, item in enumerate(dependencies):
                    c_tipo = item.get("type", "-")
                    c_name = item.get("name", "-")
                    c_url  = item.get("url", "-")
                    c_req  = item.get("present_in_requirements", "❌")
                    c_poe  = item.get("present_in_poetry", "❌")
                    
                    r_tipo, r_comp, r_sorg, r_req, r_poe, r_az = st.columns([1, 2, 3, 1.5, 1.5, 1.5])
                    with r_tipo: st.write(c_tipo)
                    with r_comp: st.write(c_name)
                    with r_sorg: st.write(c_url)
                    with r_req:  st.write(c_req)
                    with r_poe:  st.write(c_poe)
                    
                    with r_az:
                        # Mappatura pulita del nome file atteso dallo storage backend
                        clean_repo_name = c_url.replace("https://github.com/", "").replace("/", "-").replace(".git", "")
                        expected_filename = f"{clean_repo_name}-sbom.json"
                        
                        deep_results = st.session_state.get("deep_sbom_results", {})
                        available_sboms = deep_results.get("sboms", {}) if deep_results else {}
                        
                        if expected_filename in available_sboms:
                            st.download_button(
                                label="⬇️ SBOM",
                                data=available_sboms[expected_filename],
                                file_name=expected_filename,
                                mime="application/json",
                                key=f"dl_row_{clean_repo_name}_{idx}",
                                use_container_width=True
                            )
                        else:
                            st.button(
                                label="🚫 Non Disp.", 
                                key=f"disabled_row_{idx}", 
                                disabled=True,
                                use_container_width=True
                            )
            else:
                st.info("Nessuna lista componenti strutturata disponibile.")
        
        # Tab 1: Link GitHub
        with tabs[1]:
            if git_repos:
                for r in sorted(list(set(git_repos))):
                    st.markdown(f"- [{r}]({r})" if r.startswith("http") else f"- {r}")
            else:
                st.info("Nessuna repository GitHub mappata come dipendenza diretta.")

        # Tab Matrice di Confronto
        current_tab_idx = 2
        if comparison_report:
            with tabs[current_tab_idx]:
                if result.get("github_run_url"):
                    st.markdown(f"🌐 [Link alla Run di GitHub Actions]({result.get('github_run_url')})")
                st.text_area("Log di Confronto:", value=comparison_report, height=300)
            current_tab_idx += 1

        # Tab Requirements JSON
        if raw_req:
            with tabs[current_tab_idx]:
                st.markdown("### File `trivy_requirements.json` generato")
                st.download_button("⬇️ Scarica", data=raw_req, file_name="trivy_requirements.json", mime="application/json", key="btn_dl_req")
                st.code(raw_req, language="json")
            current_tab_idx += 1

        # Tab Poetry JSON
        if raw_poe:
            with tabs[current_tab_idx]:
                st.markdown("### File `trivy_poetry.json` generato")
                st.download_button("⬇️ Scarica", data=raw_poe, file_name="trivy_poetry.json", mime="application/json", key="btn_dl_poe")
                st.code(raw_poe, language="json")
            current_tab_idx += 1

        # Ultimo Tab: JSON Grezzo Backend
        with tabs[current_tab_idx]:
            st.code(json.dumps(result, indent=2), language="json")
            st.download_button("⬇️ Scarica JSON Completo Backend", data=json.dumps(result, indent=2), file_name="sbom_full_output.json", mime="application/json", key="btn_dl_full_backend")

else:
    st.warning("⚠️ Completa il punto precedente e clicca su 'Invia e Mantieni in Memoria sul Server' per sbloccare l'analisi.")