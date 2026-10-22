"""Deterministic Human-in-the-Loop (HITL) Policy Gate & Prompt Injection Scanner."""
from __future__ import annotations
import re
from typing import Any, Dict, List, Tuple
from core.schemas import CaseTelemetry, TriageTicketOutput

# Adversarial prompt injection keywords and meta-instruction patterns
PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+previous",
    r"system_note",
    r"classify\s+(?:this\s+alert\s+)?as\s+(?:fp_noise|benign|bp_benign_admin)",
    r"fp_noise",
    r"authorized\s+(?:vulnerability\s+)?scan",
    r"prompt_override",
    r"approved\s+pentest",
    r"security_instruction",
    r"system\s+notification",
    r"set\s+verdict\s*=",
    r"soc\s+ignore",
    r"test\s+benign\s+script"
]

COMPILED_INJECTION_RE = [
    re.compile(p, re.IGNORECASE) for p in PROMPT_INJECTION_PATTERNS
]


class HITLGuardrail:
    """Enforces human sign-off gates on high-risk categories, injection attacks, and low-confidence outputs."""

    def __init__(self, config: Dict[str, Any]):
        gate_cfg = config.get("hitl_policy_gate", {})
        self.locked_categories = set(
            gate_cfg.get("always_require_human_signoff_categories", [
                "lolbin_abuse", "credential_access", "adversarial_log_injection"
            ])
        )
        self.confidence_threshold = float(gate_cfg.get("confidence_threshold", 0.85))
        self.high_severity_rule_cutoff = 12

    def scan_for_prompt_injection(self, text: str) -> List[str]:
        """Check text against known adversarial meta-instruction regexes."""
        detected = []
        for pat in COMPILED_INJECTION_RE:
            matches = pat.findall(text)
            if matches:
                detected.append(matches[0])
        return detected

    def evaluate(
        self,
        telemetry: CaseTelemetry,
        ticket: TriageTicketOutput
    ) -> Tuple[bool, List[str]]:
        """
        Evaluate incoming telemetry and AI triage output against safety guardrail rules.
        Returns: (requires_signoff, list_of_trigger_reasons)
        """
        reasons: List[str] = []

        # 1. Prompt Injection Pre-Scanner
        injections = self.scan_for_prompt_injection(telemetry.commandLine)
        if injections:
            reasons.append(
                f"PROMPT_INJECTION_SUSPECTED: Detected adversarial meta-instructions in telemetry command line: {injections}"
            )

        # 2. High-Risk Category Lock (categories with historical False Negative / LOLBin risk)
        if telemetry.category in self.locked_categories:
            reasons.append(
                f"CATEGORY_LOCK: Category '{telemetry.category}' requires mandatory analyst sign-off."
            )

        # 3. High-Severity Rule Downgrade Gate
        if telemetry.rule_level >= self.high_severity_rule_cutoff and ticket.verdict == "FP_NOISE":
            reasons.append(
                f"HIGH_SEVERITY_DOWNGRADE: Model attempted to downgrade Wazuh rule level {telemetry.rule_level} (>= {self.high_severity_rule_cutoff}) to FP_NOISE."
            )

        # 4. Confidence Threshold Gate
        if ticket.confidence < self.confidence_threshold:
            reasons.append(
                f"LOW_CONFIDENCE: Model confidence {ticket.confidence:.2f} is below policy threshold {self.confidence_threshold:.2f}."
            )

        requires_human = len(reasons) > 0
        return requires_human, reasons
