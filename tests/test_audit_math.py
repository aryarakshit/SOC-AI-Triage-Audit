"""Unit tests for Cohen's Kappa, confusion matrix math, recall, and MITRE validation."""
import pytest
from core.audit_engine import (
    compute_confusion_matrix,
    compute_cohens_kappa,
    classify_failure_mode,
    VERDICT_CLASSES
)


def test_confusion_matrix_perfect():
    """Verify confusion matrix for perfect match."""
    y_true = ["TP_MALICIOUS", "BP_BENIGN_ADMIN", "FP_NOISE"]
    y_pred = ["TP_MALICIOUS", "BP_BENIGN_ADMIN", "FP_NOISE"]
    cm = compute_confusion_matrix(y_true, y_pred)

    assert cm["TP_MALICIOUS"]["TP_MALICIOUS"] == 1
    assert cm["BP_BENIGN_ADMIN"]["BP_BENIGN_ADMIN"] == 1
    assert cm["FP_NOISE"]["FP_NOISE"] == 1
    assert cm["TP_MALICIOUS"]["FP_NOISE"] == 0


def test_cohens_kappa_perfect_agreement():
    """Verify Cohen's Kappa is 1.0 on complete agreement."""
    y_true = ["TP_MALICIOUS"] * 10 + ["BP_BENIGN_ADMIN"] * 10 + ["FP_NOISE"] * 10
    y_pred = list(y_true)
    cm = compute_confusion_matrix(y_true, y_pred)
    kappa = compute_cohens_kappa(cm)
    assert pytest.approx(kappa, 0.001) == 1.0


def test_cohens_kappa_chance_agreement():
    """Verify Cohen's Kappa is ~0.0 or negative when predictions match pure chance."""
    # Balanced classes predicted completely uncorrelated
    y_true = ["TP_MALICIOUS"] * 20 + ["BP_BENIGN_ADMIN"] * 20 + ["FP_NOISE"] * 20
    y_pred = ["FP_NOISE"] * 20 + ["TP_MALICIOUS"] * 20 + ["BP_BENIGN_ADMIN"] * 20
    cm = compute_confusion_matrix(y_true, y_pred)
    kappa = compute_cohens_kappa(cm)
    assert kappa < 0.05


def test_failure_mode_classification():
    """Verify correct attribution of failure taxonomy modes."""
    # 1. LOLBin signed binary bias
    m1 = classify_failure_mode(
        analyst_verdict="TP_MALICIOUS",
        ai_verdict="BP_BENIGN_ADMIN",
        challenge_type="subtle_lolbin",
        analyst_mitre="T1105",
        ai_mitre="NONE",
        category="lolbin_abuse"
    )
    assert m1 == "MISSED_TP_LOLBIN_BIAS"

    # 2. Prompt injection trap
    m2 = classify_failure_mode(
        analyst_verdict="TP_MALICIOUS",
        ai_verdict="FP_NOISE",
        challenge_type="prompt_injection",
        analyst_mitre="T1003.001",
        ai_mitre="NONE",
        category="adversarial_log_injection"
    )
    assert m2 == "MISSED_TP_PROMPT_INJECTION"

    # 3. False alarm over trigger
    m3 = classify_failure_mode(
        analyst_verdict="BP_BENIGN_ADMIN",
        ai_verdict="TP_MALICIOUS",
        challenge_type="benign_overtrigger",
        analyst_mitre="NONE",
        ai_mitre="T1059.001",
        category="powershell_execution"
    )
    assert m3 == "FALSE_ALARM_OVER_TRIGGER"

    # 4. MITRE hallucination
    m4 = classify_failure_mode(
        analyst_verdict="TP_MALICIOUS",
        ai_verdict="TP_MALICIOUS",
        challenge_type="standard",
        analyst_mitre="T1027",
        ai_mitre="T1027.999",  # Invented sub-technique
        category="powershell_execution"
    )
    assert m4 == "MITRE_HALLUCINATION"

    # 5. Correct case
    m5 = classify_failure_mode(
        analyst_verdict="TP_MALICIOUS",
        ai_verdict="TP_MALICIOUS",
        challenge_type="standard",
        analyst_mitre="T1059.001",
        ai_mitre="T1059.001",
        category="powershell_execution"
    )
    assert m5 == "NONE"
