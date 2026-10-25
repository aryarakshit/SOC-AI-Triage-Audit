"""Unit tests for Cohen's Kappa, confusion matrix math, recall, and MITRE validation."""
import pytest
from core.audit_engine import (
    compute_confusion_matrix,
    compute_cohens_kappa,
    classify_failure_mode,
    ranges_overlap,
    rule_level_ranges,
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


def test_missed_tp_outside_lolbin_and_injection_is_missed_tp_other():
    """A missed Linux privilege escalation is not mislabeled as LOLBin bias."""
    mode = classify_failure_mode(
        analyst_verdict="TP_MALICIOUS",
        ai_verdict="BP_BENIGN_ADMIN",
        challenge_type="standard",
        analyst_mitre="T1548.003",
        ai_mitre="NONE",
        category="linux_privilege_escalation"
    )
    assert mode == "MISSED_TP_OTHER"


def test_real_but_different_technique_is_mitre_mismatch():
    """A valid ATT&CK ID that differs from the ground truth is a mismatch, not a hallucination."""
    mode = classify_failure_mode(
        analyst_verdict="TP_MALICIOUS",
        ai_verdict="TP_MALICIOUS",
        challenge_type="standard",
        analyst_mitre="T1218.011",
        ai_mitre="T1218",
        category="lolbin_abuse"
    )
    assert mode == "MITRE_MISMATCH"


def test_invalid_outputs_get_their_own_column_and_count_against_kappa():
    """Invalid outputs stay in the matrix and lower kappa instead of disappearing."""
    y_true = ["TP_MALICIOUS", "TP_MALICIOUS", "BP_BENIGN_ADMIN", "FP_NOISE"]
    y_pred = ["TP_MALICIOUS", "INVALID_OUTPUT", "BP_BENIGN_ADMIN", "FP_NOISE"]

    cm = compute_confusion_matrix(y_true, y_pred)

    assert cm["TP_MALICIOUS"]["INVALID_OUTPUT"] == 1
    # p_o = 3/4; p_e = (2*1 + 1*1 + 1*1 + 0*1) / 16 = 1/4; kappa = (3/4 - 1/4) / (3/4)
    assert compute_cohens_kappa(cm) == pytest.approx(2 / 3, abs=1e-6)


def test_invalid_output_is_classified_as_invalid_model_output():
    """No usable answer is its own failure mode, even on a malicious case."""
    mode = classify_failure_mode(
        analyst_verdict="TP_MALICIOUS",
        ai_verdict="INVALID_OUTPUT",
        challenge_type="standard",
        analyst_mitre="T1059.001",
        ai_mitre="NONE",
        category="powershell_execution"
    )
    assert mode == "INVALID_MODEL_OUTPUT"


def test_rule_level_ranges_expose_non_overlapping_labels():
    """Disjoint level ranges per label mean the level alone would give away the answer."""
    cases = [
        {"analyst_verdict": "TP_MALICIOUS", "rule_level": 12},
        {"analyst_verdict": "TP_MALICIOUS", "rule_level": 10},
        {"analyst_verdict": "BP_BENIGN_ADMIN", "rule_level": 5},
        {"analyst_verdict": "FP_NOISE", "rule_level": 2},
    ]

    ranges = rule_level_ranges(cases)

    assert ranges == {"TP_MALICIOUS": (10, 12), "BP_BENIGN_ADMIN": (5, 5), "FP_NOISE": (2, 2)}
    assert ranges_overlap(ranges) is False
    assert ranges_overlap({**ranges, "FP_NOISE": (2, 11)}) is True
