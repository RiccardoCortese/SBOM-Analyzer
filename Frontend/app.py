import streamlit as st
import requests
import pandas as pd
import json
from streamlit_agraph import agraph, Node, Edge, Config
import re

from components.configuration_target import render_config_target
from components.docker_analysis import render_docker_section
from components.standard_analysis import render_standard_analysis
from components.custom_analysis import render_custom_analysis
from components.merge_sboms import render_merge_sboms
from components.graph_visualization import render_graph_section
from components.search_component import render_search_component
from components.scan_vulnerability import render_scan_vulnerability

# ============================================================
# CONFIGURAZIONE APP STREAMLIT
# ============================================================

st.set_page_config(page_title="SBOM Analyzer", layout="wide")
st.title("SBOM Analyzer")

BACKEND_URL = "http://127.0.0.1:8000"

# ============================================================
# STATE MANAGEMENT (Streamlit session_state)
# Serve per mantenere lo stato tra return della UI
# ============================================================
# Inizializzazione Stati Permanenti di Streamlit
if "sbom_ready" not in st.session_state:
    st.session_state.sbom_ready = False
if "saved_repo" not in st.session_state:
    st.session_state.saved_repo = ""
if "saved_branch" not in st.session_state:
    st.session_state.saved_branch = "dev"
if "saved_format" not in st.session_state:
    st.session_state.saved_format = "entrambi"
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = {}
if "merged_results" not in st.session_state:
    st.session_state.merged_results = None
if "analysis_results_standard" not in st.session_state:
    st.session_state.analysis_results_standard = None
if "analysis_results_advanced" not in st.session_state:
    st.session_state.analysis_results_advanced = False
if "deep_sbom_results" not in st.session_state:
    st.session_state.deep_sbom_results = None
if "docker_analyzed" not in st.session_state:
    st.session_state.docker_analyzed = False
if "docker_results" not in st.session_state:
    st.session_state.docker_results = {"graphs": {}, "hierarchy_with_weights": {}}


            
# ============================================================
# RENDER DEI COMPONENTI DELLA DASHBOARD
# ============================================================

# Configurazione Target e Discovery Iniziale
render_config_target(BACKEND_URL)

if "found_files" in st.session_state and st.session_state.found_files:
    # Analisi File Standard (Requirements, Poetry, ecc.)
    render_standard_analysis(BACKEND_URL)
    
    # Analisi File Custom / Immagini Docker rilevate nel Dockerfile
    # in questo caso nonmi serve perchè ci sono già le immagini docker nel parsing del dockerfile
    # la tengo commentata per ora
    #render_custom_analysis(BACKEND_URL)

# Sezione Merge Artefatti SBOM e generazione grafici
render_merge_sboms(BACKEND_URL)

# Sezione Analisi Immagine Docker e Confronto
render_docker_section(BACKEND_URL)

# Sezione Vulnerability Scan 
render_scan_vulnerability(BACKEND_URL)

# Sezione Ricerca Componenti specifici e Visualizzazione Grafi
render_search_component(BACKEND_URL)

# Sezione Grafi e Visualizzazione Avanzata delle Dipendenze
render_graph_section(BACKEND_URL)