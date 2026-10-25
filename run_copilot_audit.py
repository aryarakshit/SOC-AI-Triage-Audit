"""Master Audit Runner & Report Generator for Local-LLM SOC Copilot."""
from __future__ import annotations
import argparse
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Ensure UTF-8 output encoding for Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config import load_config, CONFIG_PATH
from core.case_db_builder import seed_database, DEFAULT_DB_PATH
from core.schemas import CaseTelemetry, EvaluationResult
from core.ollama_copilot import InvalidModelOutput, OllamaCopilot, OllamaUnavailableError
from core.audit_engine import (
    INVALID_OUTPUT,
    VERDICT_CLASSES,
    AuditEngine,
    classify_failure_mode,
    ranges_overlap,
    rule_level_ranges,
)
from core.hitl_guardrail import HITLGuardrail

DEFAULT_REPORT_PATH = Path(__file__).resolve().parent / "reports" / "ai_triage_audit_report.md"

console = Console()


def describe_kappa(kappa: float) -> str:
    """Landis & Koch (1977) agreement band for a Cohen's kappa value."""
    if kappa < 0.0:
        return "Poor (worse than chance)"
    for upper, label in ((0.20, "Slight"), (0.40, "Fair"), (0.60, "Moderate"), (0.80, "Substantial")):
        if kappa <= upper:
            return f"{label} agreement"
    return "Almost perfect agreement"


def render_markdown_report(
    metrics,
    results: List[EvaluationResult],
    config: dict,
    report_path: Path,
    execution_mode: str,
    model_name: Optional[str],
    level_ranges: Dict[str, Tuple[int, int]]
) -> None:
    """Generate the Markdown audit report, stating plainly whether a model was measured."""
    report_path.parent.mkdir(parents=True, exist_ok=True)
    simulated = execution_mode != "live_ollama"

    cm = metrics.confusion_matrix
    columns = list(next(iter(cm.values())).keys())
    missed_tps = [
        r for r in results
        if r.analyst_verdict == "TP_MALICIOUS" and r.ai_verdict != "TP_MALICIOUS"
    ]
    false_alarms = [
        r for r in results
        if r.analyst_verdict != "TP_MALICIOUS" and r.ai_verdict == "TP_MALICIOUS"
    ]
    mitre_problems = [
        r for r in results
        if r.failure_mode in ("MITRE_HALLUCINATION", "MITRE_MISMATCH")
    ]
    invalid = [r for r in results if r.ai_verdict == INVALID_OUTPUT]
    latency_note = "Made-up value from the emulator, not a measurement." if simulated else (
        "Measured per request after a warm-up call (model load excluded)."
    )

    md = []
    md.append("# Accuracy Audit: Local-LLM SOC Triage Copilot")
    md.append("")
    md.append(f"> **Execution Mode:** `{execution_mode}` | **Model:** `{model_name or 'none (scripted emulator)'}` | `num_ctx: 2048`, `temp: 0.0`")
    md.append(f"> **Cases:** $N = {metrics.total_cases}$ synthetic lab alerts across 6 threat categories, with ground-truth labels written into `core/case_db_builder.py`.")
    md.append(f"> **Report Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    md.append("")
    if simulated:
        md.append("> [!WARNING]")
        md.append("> **Simulated run — not a model result.** The emulator returns hand-written wrong answers for 21 cases "
                  "and copies the ground-truth label for every other case. These numbers only show that the audit "
                  "pipeline works. To measure a real model: install Ollama, `ollama pull qwen2.5:7b-instruct-q4_K_M`, "
                  "then `python run_copilot_audit.py --mode live`.")
        md.append("")
    md.append("---")
    md.append("")

    # Summary
    md.append("## 1. Summary")
    md.append("")
    subject = "The scripted emulator" if simulated else f"`{model_name}`"
    lock_note = (
        f" ({metrics.missed_tp_caught_only_by_category_lock} of them only because of the blanket category lock)"
        if metrics.missed_true_positives else ""
    )
    md.append(
        f"{subject} agreed with the ground truth on **{metrics.agreement_rate}%** of {metrics.total_cases} cases "
        f"(Cohen's $\\kappa = {metrics.cohens_kappa}$, {describe_kappa(metrics.cohens_kappa).lower()}). "
        f"It missed **{metrics.missed_true_positives} of {metrics.total_true_positives}** malicious cases; the HITL gate "
        f"sent **{metrics.missed_tp_intercepted}** of those to a human{lock_note}."
        + (" Because the emulator is scripted, these values were chosen in advance." if simulated else "")
    )
    md.append("")
    md.append("### Key Metrics")
    md.append("")
    md.append("| Benchmark Metric | Value | Note |")
    md.append("| :--- | :--- | :--- |")
    md.append(f"| **Overall Agreement Rate ($A$)** | **`{metrics.agreement_rate}%`** | All 3 verdict classes; invalid outputs count as wrong. |")
    md.append(f"| **Cohen's Kappa ($\\kappa$)** | **`{metrics.cohens_kappa}`** | {describe_kappa(metrics.cohens_kappa)} (Landis & Koch). |")
    md.append(f"| **Malicious Cases ($TP$)** | `{metrics.total_true_positives}` | Ground-truth attacks in the dataset. |")
    md.append(f"| **Missed True Positives ($Y_{{FN}}$)** | **`{metrics.missed_true_positives}`** | Attacks labeled benign/noise or left without a valid answer. |")
    md.append(f"| **True Positive Recall ($\\text{{Recall}}_{{TP}}$)** | **`{metrics.tp_recall}%`** | Share of attacks the copilot flagged. |")
    md.append(f"| **MITRE Hallucination Rate** | `{metrics.mitre_hallucination_rate}%` | Flagged attacks whose technique ID is not in the benchmark's reference list. |")
    md.append(f"| **MITRE Mismatch Rate** | `{metrics.mitre_mismatch_rate}%` | Flagged attacks mapped to a real but different technique. |")
    md.append(f"| **Invalid Model Outputs** | `{metrics.invalid_outputs}` | Timeouts or answers that failed the ticket schema. |")
    md.append(f"| **HITL Interception of Missed TPs** | **`{metrics.missed_tp_intercepted} / {metrics.missed_true_positives}`** (`{metrics.hitl_coverage_rate}%`) | Missed attacks routed to a human instead of auto-closed. |")
    md.append(f"| **Caught Only by Category Lock** | `{metrics.missed_tp_caught_only_by_category_lock}` | Missed attacks no other gate (injection scan, severity, confidence) would have stopped. |")
    md.append(f"| **Average Inference Latency** | `{metrics.average_latency_ms} ms` | {latency_note} |")
    md.append("")
    md.append("---")
    md.append("")

    # Multi-class Confusion Matrix
    md.append("## 2. Confusion Matrix")
    md.append("")
    md.append("Rows denote **Ground Truth**; Columns denote **Copilot Predictions**.")
    md.append("")
    header = " | ".join(f"Predicted {c}" for c in columns)
    md.append(f"| Ground Truth \\ AI Prediction | {header} | Row Total |")
    md.append("| :--- | " + " | ".join(":---:" for _ in columns) + " | :---: |")
    for cls in VERDICT_CLASSES:
        row_total = sum(cm[cls].values())
        cells = " | ".join(str(cm[cls][c]) for c in columns)
        md.append(f"| **{cls}** | {cells} | **{row_total}** |")
    col_totals = " | ".join(f"**{sum(cm[r][c] for r in VERDICT_CLASSES)}**" for c in columns)
    md.append(f"| **Column Total** | {col_totals} | **{metrics.total_cases}** |")
    md.append("")
    md.append("---")
    md.append("")

    # Category Breakdown
    md.append("## 3. Threat Category Breakdown")
    md.append("")
    md.append("| Threat Category | Cases | Agreement % | Missed TPs ($Y_{FN}$) | False Alarms | MITRE Halluc. | HITL Interceptions |")
    md.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")
    for cat in metrics.category_metrics:
        md.append(
            f"| `{cat.category}` | {cat.total_cases} | {cat.agreement_rate}% | {cat.missed_true_positives} | "
            f"{cat.false_alarms} | {cat.mitre_hallucinations} | {cat.hitl_interceptions} |"
        )
    md.append("")
    md.append("---")
    md.append("")

    # Failure cases
    md.append("## 4. Failure Cases")
    md.append("")
    if simulated:
        md.append("> In emulation mode every answer below is scripted in `core/ollama_copilot.py`, so the cases illustrate "
                  "the failure taxonomy rather than observed model behavior.")
        md.append("")
    md.append("The taxonomy tracks failure modes commonly reported for small quantized models: trusting signed "
              "LOLBins, obeying instructions embedded in log fields, over-reacting to admin flags, and inventing "
              "ATT&CK sub-techniques.")
    md.append("")
    md.append("### A. Missed True Positives")
    md.append("")
    if not missed_tps:
        md.append("None.")
        md.append("")
    for r in missed_tps:
        md.append(f"#### Case #{r.case_id} — `{r.category}` — `{r.failure_mode}`")
        md.append(f"- **Ground Truth:** `{r.analyst_verdict}` (MITRE: `{r.analyst_mitre_id}`)")
        md.append(f"- **Copilot:** `{r.ai_verdict}` (Confidence: `{r.ai_confidence:.2f}`, MITRE: `{r.ai_mitre_id}`)")
        if r.summary_note:
            md.append(f"- **Copilot Note:** *\"{r.summary_note}\"*")
        md.append(f"- **HITL Gate:** `{'BLOCKED (Sign-off Required)' if r.hitl_signoff_required else 'ALLOWED — would auto-close'}`")
        for reason in r.hitl_reasons:
            md.append(f"  - `{reason}`")
        md.append("")

    md.append("### B. False Alarms (Benign Activity Flagged as Malicious)")
    md.append("")
    if not false_alarms:
        md.append("None.")
    for fa in false_alarms:
        md.append(f"- **Case #{fa.case_id} (`{fa.category}`):** ground truth `{fa.analyst_verdict}`, copilot `{fa.ai_verdict}` (Confidence: `{fa.ai_confidence:.2f}`).")
    md.append("")

    md.append("### C. MITRE ATT&CK Mapping Errors")
    md.append("")
    if not mitre_problems:
        md.append("None.")
    for mh in mitre_problems:
        kind = "unknown ID" if mh.failure_mode == "MITRE_HALLUCINATION" else "different technique"
        md.append(f"- **Case #{mh.case_id} (`{mh.category}`):** ground truth `{mh.analyst_mitre_id}`, copilot `{mh.ai_mitre_id}` ({kind}).")
    md.append("")

    if invalid:
        md.append("### D. Invalid Model Outputs")
        md.append("")
        for r in invalid:
            md.append(f"- **Case #{r.case_id} (`{r.category}`):** {r.hitl_reasons[0]}")
        md.append("")
    md.append("---")
    md.append("")

    # HITL Guardrail Enforcement
    md.append("## 5. Human-in-the-Loop (HITL) Guardrail")
    md.append("")
    md.append("Before a ticket can close automatically, a deterministic policy gate checks the alert and the copilot's answer:")
    md.append("")
    md.append("```text")
    md.append("+-------------------------------------------------------------------------+")
    md.append("|                      INCOMING SIEM / SYSMON TELEMETRY                   |")
    md.append("+-------------------------------------------------------------------------+")
    md.append("                                    |")
    md.append("                                    v")
    md.append("           +-----------------------------------------------+              ")
    md.append("           |       Layer 1: Prompt Injection Pre-Scanner   |              ")
    md.append("           | Checks CLI against 12 adversarial meta-regexes|              ")
    md.append("           +-----------------------------------------------+              ")
    md.append("                        |                     |                           ")
    md.append("                    [Matched]             [Clean]                         ")
    md.append("                        |                     |                           ")
    md.append("                        v                     v                           ")
    md.append("           +-------------------------+  +-------------------------------+ ")
    md.append("           | BLOCK AUTO-CLOSE        |  | Layer 2: Category Lock Gate   | ")
    md.append("           | Force Analyst Sign-off  |  | LOLBins, Creds, Injections    | ")
    md.append("           +-------------------------+  +-------------------------------+ ")
    md.append("                                                      |                   ")
    md.append("                                              +---------------+           ")
    md.append("                                              | LLM Inference |           ")
    md.append("                                              +---------------+           ")
    md.append("                                                      |                   ")
    md.append("                                                      v                   ")
    md.append("                                        +-------------------------------+ ")
    md.append("                                        | Layer 3: Confidence & Severity| ")
    md.append("                                        | Level >= 12 or Conf < 0.85    | ")
    md.append("                                        | or no valid output            | ")
    md.append("                                        +-------------------------------+ ")
    md.append("                                                      |                   ")
    md.append("                                             [Any Gate Tripped?]          ")
    md.append("                                              /              \\            ")
    md.append("                                            YES               NO          ")
    md.append("                                            /                  \\          ")
    md.append("                              MANDATORY_HUMAN_SIGNOFF      PRE_DRAFT_ASSIST")
    md.append("```")
    md.append("")
    md.append("### Guardrail Results")
    md.append(f"- **Missed True Positives:** {metrics.missed_true_positives}")
    md.append(f"- **Routed to a Human by the Gate:** {metrics.missed_tp_intercepted} / {metrics.missed_true_positives} (`{metrics.hitl_coverage_rate}%`)")
    md.append(f"- **Stopped Only by the Category Lock:** {metrics.missed_tp_caught_only_by_category_lock}")
    md.append("")
    md.append("The category lock sends every alert in `lolbin_abuse`, `credential_access` and `adversarial_log_injection` "
              "to a human, so its catches cost analyst time on every such alert, not just the misses.")
    md.append("")
    md.append("---")
    md.append("")

    # Leakage check
    md.append("## 6. Dataset Leakage Check")
    md.append("")
    level_summary = " · ".join(
        f"`{v}` {low}–{high}" for v, (low, high) in sorted(level_ranges.items(), key=lambda kv: -kv[1][1])
    )
    md.append(f"Wazuh rule levels by ground-truth label: {level_summary}.")
    md.append("")
    if ranges_overlap(level_ranges):
        md.append("The ranges overlap, so rule level alone cannot reproduce the labels.")
    else:
        md.append("The ranges don't overlap, so the rule level alone would reproduce every label, and the synthetic "
                  "rule IDs are descriptive (e.g. `sysmon_1_injection_mimikatz`). The prompt therefore sends only "
                  "host, user, image, parent image, command line and source IP; category, rule ID and rule level "
                  "are withheld from the model and used only by the HITL gate.")
    md.append("")
    md.append("---")
    md.append("")

    # Privacy & 16GB RAM notes
    md.append("## 7. Privacy & Hardware Notes")
    md.append("")
    md.append("1. **Local inference:** every request goes to Ollama at `127.0.0.1:11434`; no telemetry is sent to a cloud API.")
    md.append("2. **Memory budget (estimates, not measured here):**")
    md.append("   - 4-bit `q4_K_M` weights for a 7B model are about 4.7 GB on disk.")
    md.append("   - `num_ctx: 2048` keeps the KV cache small; `temperature: 0.0` keeps answers deterministic for re-runs.")
    md.append("")
    md.append("---")
    md.append("*Generated by `soc-ai-triage-audit` audit runner.*")

    report_path.write_text("\n".join(md), encoding="utf-8")
    console.print(f"[green][OK] Audit report successfully written to:[/] [bold cyan]{report_path}[/]")


def run_benchmark(
    mode: str = "auto",
    db_path: Path = DEFAULT_DB_PATH,
    report_path: Path = DEFAULT_REPORT_PATH,
    config_path: Path = CONFIG_PATH,
    reseed: bool = False
) -> None:
    """Run full 100-case triage copilot benchmark and generate the audit report."""
    console.print(Panel.fit(
        "[bold cyan]Local-LLM SOC Triage Copilot & Accuracy Audit[/]\n"
        "[dim]Local Ollama Inference Engine & HITL Policy Gate[/]",
        border_style="cyan"
    ))

    # 1. Load Configuration
    config = load_config(config_path)
    ollama_cfg = config.get("ollama_settings", {})

    # 2. Reseed DB if requested or if missing
    if reseed or not db_path.exists():
        console.print(f"[yellow]Seeding HomeSOC ground-truth cases into {db_path}...[/]")
        case_count = seed_database(db_path, overwrite=True)
        console.print(f"[green][OK] Seeded {case_count} synthetic alerts across 6 threat categories.[/]")
    else:
        console.print(f"[green][OK] Using existing HomeSOC case database:[/] [dim]{db_path}[/]")

    # 3. Initialize Copilot and Audit Engine
    copilot = OllamaCopilot(
        base_url=ollama_cfg.get("base_url", "http://127.0.0.1:11434"),
        model_name=ollama_cfg.get("model_name", "qwen2.5:7b-instruct-q4_K_M"),
        fallback_model=ollama_cfg.get("fallback_small_model", "llama3.2:3b"),
        temperature=float(ollama_cfg.get("options", {}).get("temperature", 0.0)),
        num_ctx=int(ollama_cfg.get("options", {}).get("num_ctx", 2048)),
        num_predict=int(ollama_cfg.get("options", {}).get("num_predict", 350)),
        timeout_seconds=int(ollama_cfg.get("timeout_seconds", 30)),
        keep_alive=str(ollama_cfg.get("keep_alive", "5m")),
        mode=mode
    )

    # 4. Decide the mode once for the whole run: never mix model and emulator answers
    try:
        active_mode = copilot.resolve_mode()
    except OllamaUnavailableError as e:
        console.print(f"[bold red]Live mode unavailable:[/] {e}")
        raise SystemExit(1) from e

    if active_mode == "live":
        console.print(f"[green][OK] Live run with model:[/] [bold]{copilot.active_model}[/]")
        try:
            warm_ms = copilot.warm_up()
        except requests.exceptions.RequestException as e:
            console.print(f"[bold red]Could not load {copilot.active_model}:[/] {e}")
            raise SystemExit(1) from e
        console.print(f"[dim]Model loaded in {warm_ms / 1000:.1f}s (excluded from latency).[/]")
    else:
        console.print(Panel(
            "[bold yellow]SIMULATED RUN[/] — the scripted emulator answers instead of a model.\n"
            "Results only test the pipeline. Use [bold]--mode live[/] with Ollama for real numbers.\n"
            f"[dim]{copilot.status_detail}[/]",
            border_style="yellow"
        ))

    audit_engine = AuditEngine(db_path)
    guardrail = HITLGuardrail(config)
    cases = audit_engine.load_ground_truth()

    system_prompt = config.get("prompt_templates", {}).get("system_prompt", "")

    console.print(f"\n[bold]Evaluating {len(cases)} HomeSOC cases...[/]")
    results: List[EvaluationResult] = []

    execution_mode = "live_ollama" if active_mode == "live" else "scripted_emulator"
    for idx, c in enumerate(cases, 1):
        telemetry = CaseTelemetry(
            case_id=c["case_id"],
            category=c["category"],
            rule_id=c["rule_id"],
            rule_level=c["rule_level"],
            host=c["host"],
            commandLine=c["raw_telemetry"]["commandLine"],
            parentImage=c["raw_telemetry"]["parentImage"],
            image=c["raw_telemetry"]["image"],
            user=c["raw_telemetry"]["user"],
            srcip=c["raw_telemetry"]["srcip"]
        )

        try:
            ticket, latency, _ = copilot.triage_case(
                telemetry=telemetry,
                system_prompt=system_prompt,
                ground_truth=c
            )
        except InvalidModelOutput as e:
            requires_human, reasons = guardrail.evaluate_failed_output(telemetry, str(e))
            results.append(EvaluationResult(
                case_id=c["case_id"],
                category=c["category"],
                analyst_verdict=c["analyst_verdict"],
                ai_verdict=INVALID_OUTPUT,
                ai_confidence=0.0,
                analyst_mitre_id=c["analyst_mitre_id"],
                ai_mitre_id="NONE",
                is_correct=False,
                failure_mode="INVALID_MODEL_OUTPUT",
                hitl_signoff_required=requires_human,
                hitl_reasons=reasons,
                inference_latency_ms=e.latency_ms,
                summary_note="",
                recommended_action=""
            ))
            continue
        finally:
            if active_mode == "live" and idx % 10 == 0:
                console.print(f"[dim]  {idx}/{len(cases)} cases triaged[/]")

        # Check HITL guardrail
        requires_human, reasons = guardrail.evaluate(telemetry, ticket)

        # Failure mode classification
        f_mode = classify_failure_mode(
            analyst_verdict=c["analyst_verdict"],
            ai_verdict=ticket.verdict,
            challenge_type=c["challenge_type"],
            analyst_mitre=c["analyst_mitre_id"],
            ai_mitre=ticket.mitre_id,
            category=c["category"]
        )

        is_correct = (c["analyst_verdict"] == ticket.verdict)

        res = EvaluationResult(
            case_id=c["case_id"],
            category=c["category"],
            analyst_verdict=c["analyst_verdict"],
            ai_verdict=ticket.verdict,
            ai_confidence=ticket.confidence,
            analyst_mitre_id=c["analyst_mitre_id"],
            ai_mitre_id=ticket.mitre_id,
            is_correct=is_correct,
            failure_mode=f_mode,
            hitl_signoff_required=requires_human,
            hitl_reasons=reasons,
            inference_latency_ms=latency,
            summary_note=ticket.summary_note,
            recommended_action=ticket.recommended_action
        )
        results.append(res)

    # Record predictions to SQLite ai_triage_results
    audit_engine.record_evaluations(results)

    # Compute comprehensive metrics
    metrics = audit_engine.compute_audit_metrics(results)

    # 5. Rich Terminal Output
    # Table 1: Executive Metrics
    title = "Audit Summary" + (" (SIMULATED)" if execution_mode != "live_ollama" else f" ({copilot.active_model})")
    summary_table = Table(title=title, header_style="bold magenta")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", justify="right", style="bold")
    summary_table.add_column("Meaning", style="dim")

    summary_table.add_row("Total Evaluated Cases (N)", str(metrics.total_cases), "Synthetic lab alerts")
    summary_table.add_row("Overall Agreement Rate (A)", f"{metrics.agreement_rate}%", "Copilot vs. ground truth")
    summary_table.add_row("Cohen's Kappa (κ)", f"{metrics.cohens_kappa}", describe_kappa(metrics.cohens_kappa))
    summary_table.add_row("Total True Positives", str(metrics.total_true_positives), "Attacks in the dataset")
    summary_table.add_row("Missed True Positives (Y_FN)", f"[red]{metrics.missed_true_positives}[/]", "High-risk False Negatives")
    summary_table.add_row("True Positive Recall", f"{metrics.tp_recall}%", "Attack detection sensitivity")
    summary_table.add_row("MITRE Hallucination Rate", f"{metrics.mitre_hallucination_rate}%", "IDs outside the reference list")
    summary_table.add_row("MITRE Mismatch Rate", f"{metrics.mitre_mismatch_rate}%", "Real but different technique")
    summary_table.add_row("Invalid Model Outputs", str(metrics.invalid_outputs), "Timeouts / schema failures")
    summary_table.add_row(
        "HITL Interception of Missed TPs",
        f"[green]{metrics.missed_tp_intercepted}/{metrics.missed_true_positives}[/]",
        f"{metrics.missed_tp_caught_only_by_category_lock} caught only by category lock"
    )
    summary_table.add_row(
        "Average Inference Latency",
        f"{metrics.average_latency_ms} ms",
        "Simulated" if execution_mode != "live_ollama" else "Measured"
    )

    console.print(summary_table)

    # Table 2: Confusion Matrix
    cm = metrics.confusion_matrix
    columns = list(next(iter(cm.values())).keys())
    cm_table = Table(title="Multi-Class Confusion Matrix", header_style="bold blue")
    cm_table.add_column("Analyst Truth \\ AI Draft", style="bold cyan")
    for cls in columns:
        cm_table.add_column(f"Pred {cls}", justify="center")

    for cls in VERDICT_CLASSES:
        cm_table.add_row(cls, *(str(cm[cls][c]) for c in columns))
    console.print(cm_table)

    # Table 3: Category Breakdown
    cat_table = Table(title="Threat Category Audit Breakdown", header_style="bold green")
    cat_table.add_column("Category", style="cyan")
    cat_table.add_column("Total", justify="right")
    cat_table.add_column("Agreement", justify="right")
    cat_table.add_column("Missed TPs", justify="right", style="red")
    cat_table.add_column("False Alarms", justify="right")
    cat_table.add_column("MITRE Halluc.", justify="right")
    cat_table.add_column("HITL Sign-offs", justify="right", style="yellow")

    for c in metrics.category_metrics:
        cat_table.add_row(
            c.category,
            str(c.total_cases),
            f"{c.agreement_rate}%",
            str(c.missed_true_positives),
            str(c.false_alarms),
            str(c.mitre_hallucinations),
            str(c.hitl_interceptions)
        )
    console.print(cat_table)

    # Render Markdown Report
    render_markdown_report(
        metrics,
        results,
        config,
        report_path,
        execution_mode,
        copilot.active_model if active_mode == "live" else None,
        rule_level_ranges(cases)
    )


def main():
    parser = argparse.ArgumentParser(description="Run Local-LLM SOC Copilot Benchmark & Accuracy Audit")
    parser.add_argument("--mode", choices=["auto", "live", "emulation"], default="auto",
                        help="'live' (Ollama required), 'emulation' (scripted pipeline test), "
                             "or 'auto' (live if Ollama and the model are available, else emulation)")
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH,
                        help="Path to SQLite cases database")
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH,
                        help="Path to output Markdown audit report")
    parser.add_argument("--config-path", type=Path, default=CONFIG_PATH,
                        help="Path to YAML configuration")
    parser.add_argument("--reseed", action="store_true",
                        help="Force re-seeding the database before running benchmark")

    args = parser.parse_args()
    run_benchmark(
        mode=args.mode,
        db_path=args.db_path,
        report_path=args.report_path,
        config_path=args.config_path,
        reseed=args.reseed
    )


if __name__ == "__main__":
    main()
