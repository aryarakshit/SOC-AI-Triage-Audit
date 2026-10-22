# Local-LLM SOC Triage Copilot & Empirical Accuracy Audit (`soc-ai-triage-audit`)

## What This Is

A privacy-preserving, 100% local AI triage copilot powered by Ollama (targeting `qwen2.5:7b-instruct-q4_K_M` and `llama3.2:3b`), designed to ingest raw SIEM/Wazuh/Sysmon alerts from a HomeSOC SQLite database and output structured JSON ticket notes, MITRE ATT&CK mappings, and triage verdicts (`TP_MALICIOUS`, `BP_BENIGN_ADMIN`, `FP_NOISE`). The system includes an empirical accuracy audit engine benchmarked against $N = 100$ verified analyst cases, failure taxonomy classification, and a deterministic Human-in-the-Loop (HITL) Policy Gate that prevents auto-closure of high-risk threat categories.

## Core Value

Empirical transparency and data privacy over AI hype: rigorously evaluating where small local LLMs fail (missed True Positives, LOLBin signed-binary bias, adversarial prompt injection) and enforcing fail-safe human sign-off gates.

## Key Constraints & Architecture

- **Zero Cloud Leak:** Local Ollama inference at `http://127.0.0.1:11434/api/chat` with strict context caps (`num_ctx: 2048`, `temperature: 0.0`) fitting within 16 GB RAM with lab VMs off.
- **Dual-Mode Execution:** Live Ollama execution and calibrated deterministic offline emulator matching 7B Q4 model failure distributions (~82% agreement, realistic LOLBin bias, prompt injection bypass).
- **Audit Metrics:** Multi-class confusion matrix, Cohen's Kappa ($\kappa$), False Negative counting, MITRE ATT&CK hallucination tracking.
- **HITL Guardrail Gate:** Enforces 100% human review on categories with $Y_{\text{FN}} > 0$ (`lolbin_abuse`, `credential_access`, `adversarial_log_injection`), low-confidence outputs (<0.85), high-severity rule downgrades, and detected prompt-injection payloads.

## Requirements

### Validated
- [x] Environment and Python dependencies verified (`pydantic`, `pyyaml`, `requests`, `rich`, `tabulate`, `pytest`).
- [x] GSD framework initialized.

### Active
- [ ] Phase 1: Workspace setup, config (`config/copilot_config.yaml`), `requirements.txt`.
- [ ] Phase 2: 100-Case HomeSOC Ground-Truth SQLite Database (`core/case_db_builder.py`, `data/homesoc_cases.db`).
- [ ] Phase 3: Pydantic schemas & Dual-Mode Local Ollama Copilot (`core/schemas.py`, `core/ollama_copilot.py`).
- [ ] Phase 4: Accuracy Audit Engine & Failure Taxonomy Classifier (`core/audit_engine.py`).
- [ ] Phase 5: Human-in-the-Loop (HITL) Guardrail & Unit Tests (`core/hitl_guardrail.py`, `tests/`).
- [ ] Phase 6: Master Audit Runner & Report Generation (`run_copilot_audit.py`, `reports/ai_triage_audit_report.md`).
- [ ] Phase 7: Professional GitHub README and publication preparation (`README.md`, badges, architecture, setup instructions, security disclosures, MIT license).

### Out of Scope
- Cloud LLM API calls (OpenAI, Anthropic) - strictly prohibited to preserve SOC data privacy.
- Models larger than 7B requiring >16 GB RAM.
