#  Dependency Analyzer 

Questo repository contiene il backend per **Dependency Analyzer**, un'applicazione basata su **FastAPI** progettata per analizzare e confrontare le dipendenze software di un progetto con i componenti estratti da SBOM (Software Bill of Materials) generati tramite pipeline esterne (GitHub Actions) o caricati manualmente.

Il sistema incrocia le dipendenze statiche del codice (`dependencies.json`, file `requirements.txt` estratti da Trivy, o `poetry.lock` estratti da Trivy) con gli SBOM di immagini container Docker, offrendo una panoramica accurata dei pacchetti in comune e di quelli presenti esclusivamente all'interno dell'ambiente di runtime Docker.

## Caratteristiche Principali

* **Trigger Automatico di GitHub Actions**: Avvia flussi di lavoro remoti (`sbom_static.yml` e `dynamic_sbom.yml`) direttamente tramite API REST per generare SBOM in parallelo o matrici di analisi.
* **Analisi Comparativa Avanzata**: Mappatura totale delle dipendenze del codice sorgente incrociate con i dati di Trivy (Requirements e Poetry) e il Docker SBOM.
* **Parsing Strutturato di PURL**: Supporto nativo per la classificazione dei Package URL (`purl`) per identificare librerie software (`pypi`, `github`, ecc.) o pacchetti di sistema (`deb/debian`).
* **Meccanismo di Polling Automatizzato**: Monitoraggio dello stato dei workflow remoti su GitHub con download e decompressione automatica degli artifact SBOM generati in formato ZIP.

---
