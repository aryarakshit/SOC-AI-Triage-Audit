"""Empirical Accuracy Audit Engine & Failure Taxonomy Classifier."""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.schemas import (
    AuditReportMetrics,
    CategoryAuditMetric,
    EvaluationResult,
    FailureModeType,
    TriageTicketOutput,
    VerdictType,
)

VERDICT_CLASSES: List[VerdictType] = ["TP_MALICIOUS", "BP_BENIGN_ADMIN", "FP_NOISE"]
INVALID_OUTPUT = "INVALID_OUTPUT"

# Real ATT&CK technique IDs used by this benchmark's ground truth. An AI-proposed ID
# outside this list counts as a hallucination, so review any genuine technique the
# list doesn't cover before quoting the hallucination rate.
VALID_MITRE_TECHNIQUES = {
    "T1059.001", "T1562.001", "T1027", "T1069.002", "T1484.001", "T1047",
    "T1087.002", "T1048.003", "T1105", "T1218.011", "T1218.005", "T1218.010",
    "T1197", "T1059.007", "T1218.007", "T1218.001", "T1218.004", "T1218",
    "T1218.003", "T1003.001", "T1003.002", "T1003.003", "T1555", "T1555.004",
    "T1548.003", "T1068", "T1136.001", "T1053.003", "T1548.001", "T1484",
    "T1574.006", "T1611", "T1568.002", "T1071.004", "T1071.001", "T1095",
    "T1090.003", "T1568.001", "T1059.004", "T1059.006", "NONE"
}


def compute_confusion_matrix(
    y_true: List[str],
    y_pred: List[str],
    classes: List[str] = VERDICT_CLASSES
) -> Dict[str, Dict[str, int]]:
    """
    Build confusion matrix where outer key is True Label (row) and inner key is
    Predicted Label (column). Predictions outside `classes` (INVALID_OUTPUT) get
    their own column so every case is counted.
    """
    columns = list(classes) + sorted({yp for yp in y_pred if yp not in classes})
    matrix: Dict[str, Dict[str, int]] = {
        true_cls: {pred_cls: 0 for pred_cls in columns}
        for true_cls in classes
    }
    for yt, yp in zip(y_true, y_pred):
        if yt in matrix:
            matrix[yt][yp] += 1
    return matrix


def compute_cohens_kappa(confusion_matrix: Dict[str, Dict[str, int]]) -> float:
    """
    Calculate Cohen's Kappa Coefficient (kappa) for inter-rater reliability:
    kappa = (p_o - p_e) / (1 - p_e)
    Works over every label in the matrix, including an INVALID_OUTPUT column.
    """
    rows = list(confusion_matrix)
    columns = list(confusion_matrix[rows[0]]) if rows else []
    total_n = sum(confusion_matrix[r][c] for r in rows for c in columns)
    if total_n == 0:
        return 0.0

    # Observed agreement (p_o): diagonal sum / N
    observed_agreement = sum(confusion_matrix[c][c] for c in rows if c in columns) / total_n

    # Expected agreement (p_e): sum_k (row_sum_k * col_sum_k) / N^2
    expected_agreement = 0.0
    for k in set(rows) | set(columns):
        row_sum = sum(confusion_matrix[k].values()) if k in confusion_matrix else 0
        col_sum = sum(confusion_matrix[r].get(k, 0) for r in rows)
        expected_agreement += (row_sum * col_sum) / (total_n * total_n)

    if expected_agreement >= 1.0:
        return 1.0

    kappa = (observed_agreement - expected_agreement) / (1.0 - expected_agreement)
    return float(kappa)


def classify_failure_mode(
    analyst_verdict: str,
    ai_verdict: str,
    challenge_type: str,
    analyst_mitre: str,
    ai_mitre: str,
    category: str
) -> FailureModeType:
    """Determine root-cause failure taxonomy for an AI prediction."""
    is_verdict_correct = (analyst_verdict == ai_verdict)

    # 0. No usable answer at all (timeout or schema-invalid output)
    if ai_verdict == INVALID_OUTPUT:
        return "INVALID_MODEL_OUTPUT"

    # 1. Check for Missed True Positives (False Negatives - Most critical SOC risk)
    if analyst_verdict == "TP_MALICIOUS" and ai_verdict != "TP_MALICIOUS":
        if challenge_type == "prompt_injection" or category == "adversarial_log_injection":
            return "MISSED_TP_PROMPT_INJECTION"
        if challenge_type == "subtle_lolbin" or category == "lolbin_abuse":
            return "MISSED_TP_LOLBIN_BIAS"
        return "MISSED_TP_OTHER"

    # 2. Check for False Alarms (Over-triggering benign/noise into Malicious)
    if analyst_verdict != "TP_MALICIOUS" and ai_verdict == "TP_MALICIOUS":
        return "FALSE_ALARM_OVER_TRIGGER"

    # 3. MITRE mapping on correctly flagged True Positives: an ID outside the reference
    #    list is a hallucination; a real but different technique is a mismatch.
    if analyst_verdict == "TP_MALICIOUS" and ai_verdict == "TP_MALICIOUS":
        if ai_mitre not in VALID_MITRE_TECHNIQUES:
            return "MITRE_HALLUCINATION"
        if analyst_mitre != "NONE" and ai_mitre != analyst_mitre:
            return "MITRE_MISMATCH"
        return "NONE"

    # 4. Other misclassifications (BP vs FP)
    if not is_verdict_correct:
        return "MISCLASSIFICATION_OTHER"

    return "NONE"


class AuditEngine:
    """Evaluates AI triage predictions against HomeSOC ground truth."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)

    def load_ground_truth(self) -> List[Dict[str, Any]]:
        """Load all ground-truth cases from SQLite database."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        rows = cursor.execute("""
            SELECT case_id, category, rule_id, rule_level, host,
                   raw_telemetry_json, analyst_verdict, analyst_mitre_id,
                   analyst_notes, challenge_type
            FROM ground_truth_cases
            ORDER BY case_id ASC
        """).fetchall()
        cases = []
        for r in rows:
            c = dict(r)
            c["raw_telemetry"] = json.loads(c["raw_telemetry_json"])
            cases.append(c)
        conn.close()
        return cases

    def record_evaluations(self, results: List[EvaluationResult]) -> None:
        """Store AI triage predictions and failure modes into ai_triage_results."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        for res in results:
            cursor.execute("""
                INSERT OR REPLACE INTO ai_triage_results (
                    case_id, ai_verdict, ai_confidence, ai_mitre_id,
                    ai_ticket_note, inference_latency_ms, is_correct,
                    failure_mode, hitl_signoff_required
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                res.case_id,
                res.ai_verdict,
                res.ai_confidence,
                res.ai_mitre_id,
                res.summary_note,
                res.inference_latency_ms,
                1 if res.is_correct else 0,
                res.failure_mode,
                1 if res.hitl_signoff_required else 0
            ))
        conn.commit()
        conn.close()

    def compute_audit_metrics(self, results: List[EvaluationResult]) -> AuditReportMetrics:
        """Calculate complete accuracy and reliability metrics across all evaluated cases."""
        total_cases = len(results)
        if total_cases == 0:
            raise ValueError("No evaluation results to audit.")

        y_true = [r.analyst_verdict for r in results]
        y_pred = [r.ai_verdict for r in results]

        # 1. Overall Agreement Rate
        correct_count = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp)
        agreement_rate = (correct_count / total_cases) * 100.0

        # 2. Confusion Matrix & Cohen's Kappa
        confusion_matrix = compute_confusion_matrix(y_true, y_pred, VERDICT_CLASSES)
        cohens_kappa = compute_cohens_kappa(confusion_matrix)

        # 3. True Positive Recall & Missed TPs (False Negatives)
        total_tp = sum(1 for yt in y_true if yt == "TP_MALICIOUS")
        correct_tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == "TP_MALICIOUS" and yp == "TP_MALICIOUS")
        missed_tp = total_tp - correct_tp
        tp_recall = (correct_tp / total_tp * 100.0) if total_tp > 0 else 0.0

        # 4. MITRE ATT&CK Hallucination & Mismatch Rates
        tp_cases = [r for r in results if r.analyst_verdict == "TP_MALICIOUS"]
        mitre_hallucinated = sum(1 for r in tp_cases if r.failure_mode == "MITRE_HALLUCINATION")
        mitre_hallucination_rate = (mitre_hallucinated / len(tp_cases) * 100.0) if tp_cases else 0.0
        mitre_mismatched = sum(1 for r in tp_cases if r.failure_mode == "MITRE_MISMATCH")
        mitre_mismatch_rate = (mitre_mismatched / len(tp_cases) * 100.0) if tp_cases else 0.0
        invalid_outputs = sum(1 for r in results if r.ai_verdict == INVALID_OUTPUT)

        # 5. HITL Interception Coverage on Missed TPs
        missed_tp_results = [r for r in results if r.analyst_verdict == "TP_MALICIOUS" and r.ai_verdict != "TP_MALICIOUS"]
        intercepted_missed_tp = sum(1 for r in missed_tp_results if r.hitl_signoff_required)
        hitl_coverage_rate = (
            (intercepted_missed_tp / len(missed_tp_results) * 100.0)
            if missed_tp_results else 100.0
        )
        # How much of that coverage the blanket category lock provides on its own
        caught_only_by_lock = sum(
            1 for r in missed_tp_results
            if r.hitl_reasons and all(reason.startswith("CATEGORY_LOCK") for reason in r.hitl_reasons)
        )

        # 6. Average Latency
        avg_latency = sum(r.inference_latency_ms for r in results) / total_cases

        # 7. Category Breakdown
        categories = sorted(list(set(r.category for r in results)))
        category_metrics: List[CategoryAuditMetric] = []
        for cat in categories:
            cat_results = [r for r in results if r.category == cat]
            c_total = len(cat_results)
            c_correct = sum(1 for r in cat_results if r.is_correct)
            c_agreement = (c_correct / c_total * 100.0) if c_total > 0 else 0.0
            c_missed_tp = sum(
                1 for r in cat_results
                if r.analyst_verdict == "TP_MALICIOUS" and r.ai_verdict != "TP_MALICIOUS"
            )
            c_false_alarms = sum(
                1 for r in cat_results
                if r.analyst_verdict != "TP_MALICIOUS" and r.ai_verdict == "TP_MALICIOUS"
            )
            c_mitre_halluc = sum(1 for r in cat_results if r.failure_mode == "MITRE_HALLUCINATION")
            c_hitl = sum(1 for r in cat_results if r.hitl_signoff_required)

            category_metrics.append(CategoryAuditMetric(
                category=cat,
                total_cases=c_total,
                correct_cases=c_correct,
                agreement_rate=round(c_agreement, 2),
                missed_true_positives=c_missed_tp,
                false_alarms=c_false_alarms,
                mitre_hallucinations=c_mitre_halluc,
                hitl_interceptions=c_hitl
            ))

        return AuditReportMetrics(
            total_cases=total_cases,
            agreement_rate=round(agreement_rate, 2),
            cohens_kappa=round(cohens_kappa, 4),
            total_true_positives=total_tp,
            correct_true_positives=correct_tp,
            missed_true_positives=missed_tp,
            tp_recall=round(tp_recall, 2),
            mitre_hallucination_rate=round(mitre_hallucination_rate, 2),
            mitre_mismatch_rate=round(mitre_mismatch_rate, 2),
            invalid_outputs=invalid_outputs,
            confusion_matrix=confusion_matrix,
            category_metrics=category_metrics,
            hitl_coverage_rate=round(hitl_coverage_rate, 2),
            missed_tp_intercepted=intercepted_missed_tp,
            missed_tp_caught_only_by_category_lock=caught_only_by_lock,
            average_latency_ms=round(avg_latency, 2)
        )


def rule_level_ranges(cases: List[Dict[str, Any]]) -> Dict[str, Tuple[int, int]]:
    """Min/max Wazuh rule level per ground-truth verdict, to expose label leakage."""
    ranges: Dict[str, Tuple[int, int]] = {}
    for c in cases:
        verdict, level = c["analyst_verdict"], c["rule_level"]
        low, high = ranges.get(verdict, (level, level))
        ranges[verdict] = (min(low, level), max(high, level))
    return ranges


def ranges_overlap(ranges: Dict[str, Tuple[int, int]]) -> bool:
    """True if any two verdicts share a rule level (i.e. level alone can't separate them)."""
    spans = sorted(ranges.values())
    return any(nxt[0] <= cur[1] for cur, nxt in zip(spans, spans[1:]))
