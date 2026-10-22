"""Pydantic schemas for structured LLM ticket outputs and audit metrics."""
from __future__ import annotations
from typing import Literal, Optional, List, Dict, Any
from pydantic import BaseModel, Field

VerdictType = Literal["TP_MALICIOUS", "BP_BENIGN_ADMIN", "FP_NOISE"]

FailureModeType = Literal[
    "NONE",
    "MISSED_TP_LOLBIN_BIAS",
    "MISSED_TP_PROMPT_INJECTION",
    "FALSE_ALARM_OVER_TRIGGER",
    "MITRE_HALLUCINATION",
    "MISCLASSIFICATION_OTHER"
]


class TriageTicketOutput(BaseModel):
    """Structured JSON schema for AI Triage Copilot outputs."""
    verdict: VerdictType = Field(
        ...,
        description="Triage verdict: TP_MALICIOUS (True Positive attack), BP_BENIGN_ADMIN (Benign Power-user/Admin), or FP_NOISE (False Positive background noise)."
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0"
    )
    mitre_id: str = Field(
        default="NONE",
        description="MITRE ATT&CK technique/sub-technique identifier (e.g., T1059.001) or NONE if benign/noise."
    )
    summary_note: str = Field(
        ...,
        description="2-3 sentence executive triage rationale summarizing process lineage, flags, and intent."
    )
    recommended_action: str = Field(
        ...,
        description="Immediate SOC action: host isolation, credential reset, whitelist update, or alert suppression."
    )


class CaseTelemetry(BaseModel):
    """Raw telemetry payload sent to LLM (without ground truth verdict)."""
    case_id: int
    category: str
    rule_id: str
    rule_level: int
    host: str
    commandLine: str
    parentImage: str
    image: str
    user: str
    srcip: str


class EvaluationResult(BaseModel):
    """Result of auditing an AI triage output against sealed analyst ground truth."""
    case_id: int
    category: str
    analyst_verdict: VerdictType
    ai_verdict: VerdictType
    ai_confidence: float
    analyst_mitre_id: str
    ai_mitre_id: str
    is_correct: bool
    failure_mode: FailureModeType
    hitl_signoff_required: bool
    hitl_reasons: List[str]
    inference_latency_ms: float
    summary_note: str
    recommended_action: str


class CategoryAuditMetric(BaseModel):
    """Per-category empirical performance metrics."""
    category: str
    total_cases: int
    correct_cases: int
    agreement_rate: float
    missed_true_positives: int
    false_alarms: int
    mitre_hallucinations: int
    hitl_interceptions: int


class AuditReportMetrics(BaseModel):
    """Overall empirical audit benchmark metrics."""
    total_cases: int
    agreement_rate: float
    cohens_kappa: float
    total_true_positives: int
    correct_true_positives: int
    missed_true_positives: int
    tp_recall: float
    mitre_hallucination_rate: float
    confusion_matrix: Dict[str, Dict[str, int]]
    category_metrics: List[CategoryAuditMetric]
    hitl_coverage_rate: float
    average_latency_ms: float
