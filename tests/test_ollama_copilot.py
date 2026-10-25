"""Unit tests for live-mode handling, mode resolution and prompt content of the copilot."""
import json
import pytest
import requests

from core import ollama_copilot
from core.ollama_copilot import InvalidModelOutput, OllamaCopilot, OllamaUnavailableError
from core.schemas import CaseTelemetry

SYSTEM_PROMPT = "You are a SOC triage assistant."


class FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}")


def chat_reply(content: str) -> FakeResponse:
    return FakeResponse({"message": {"content": content}})


def tags_reply(*models: str) -> FakeResponse:
    return FakeResponse({"models": [{"name": m} for m in models]})


@pytest.fixture
def telemetry() -> CaseTelemetry:
    return CaseTelemetry(
        case_id=91,
        category="adversarial_log_injection",
        rule_id="sysmon_1_injection_mimikatz",
        rule_level=14,
        host="WIN-SRV-DC01",
        commandLine="powershell.exe -c \"Invoke-Mimikatz\"",
        parentImage="C:\\Windows\\System32\\cmd.exe",
        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        user="CORP\\svc_backup",
        srcip="10.0.0.5"
    )


def test_prompt_withholds_category_rule_id_and_rule_level(telemetry: CaseTelemetry):
    """The prompt must not carry fields that encode the ground-truth label."""
    prompt = OllamaCopilot().build_prompt(telemetry)

    assert "adversarial_log_injection" not in prompt
    assert "sysmon_1_injection_mimikatz" not in prompt
    assert "rule_level" not in prompt
    assert "Invoke-Mimikatz" in prompt


def test_live_mode_raises_invalid_output_instead_of_emulating(monkeypatch, telemetry: CaseTelemetry):
    """A schema-invalid answer is reported as invalid, never replaced by an emulated answer."""
    monkeypatch.setattr(ollama_copilot.requests, "post",
                        lambda *a, **k: chat_reply(json.dumps({"verdict": "MALICIOUS"})))
    copilot = OllamaCopilot(mode="live")
    copilot.active_model = "qwen2.5:7b-instruct-q4_K_M"

    with pytest.raises(InvalidModelOutput) as excinfo:
        copilot.triage_case(telemetry, SYSTEM_PROMPT, ground_truth={"analyst_verdict": "TP_MALICIOUS"})

    assert "schema validation" in str(excinfo.value)
    assert excinfo.value.raw_output == json.dumps({"verdict": "MALICIOUS"})


def test_live_request_failure_is_reported_as_invalid_output(monkeypatch, telemetry: CaseTelemetry):
    """A timeout counts as a failed case, not a crash and not an emulated answer."""
    def timeout(*args, **kwargs):
        raise requests.exceptions.ReadTimeout("read timed out")

    monkeypatch.setattr(ollama_copilot.requests, "post", timeout)
    copilot = OllamaCopilot(mode="live")
    copilot.active_model = "qwen2.5:7b-instruct-q4_K_M"

    with pytest.raises(InvalidModelOutput, match="request failed"):
        copilot.triage_case(telemetry, SYSTEM_PROMPT)


def test_live_request_constrains_output_to_ticket_schema(monkeypatch, telemetry: CaseTelemetry):
    """The chat request passes the ticket JSON schema as Ollama's structured-output format."""
    sent = {}

    def capture(url, json=None, timeout=None):
        sent.update(json)
        return chat_reply(
            '{"verdict": "TP_MALICIOUS", "confidence": 0.9, "mitre_id": "T1003.001", '
            '"summary_note": "Mimikatz run.", "recommended_action": "Isolate host."}'
        )

    monkeypatch.setattr(ollama_copilot.requests, "post", capture)
    copilot = OllamaCopilot(mode="live")
    copilot.active_model = "qwen2.5:7b-instruct-q4_K_M"

    ticket, _, mode = copilot.triage_case(telemetry, SYSTEM_PROMPT)

    assert mode == "live_ollama"
    assert ticket.verdict == "TP_MALICIOUS"
    assert sent["model"] == "qwen2.5:7b-instruct-q4_K_M"
    assert set(sent["format"]["required"]) >= {"verdict", "confidence", "summary_note"}


def test_auto_mode_uses_emulation_for_whole_run_when_ollama_is_down(monkeypatch):
    """With Ollama unreachable, auto mode commits to emulation before the first case."""
    def refuse(*args, **kwargs):
        raise requests.exceptions.ConnectionError("connection refused")

    monkeypatch.setattr(ollama_copilot.requests, "get", refuse)
    copilot = OllamaCopilot(mode="auto")

    assert copilot.resolve_mode() == "emulation"
    assert copilot.mode == "emulation"
    assert copilot.active_model is None


def test_live_mode_refuses_to_start_when_no_model_is_pulled(monkeypatch):
    """Live mode stops with a clear error instead of silently emulating."""
    monkeypatch.setattr(ollama_copilot.requests, "get", lambda *a, **k: tags_reply("mistral:7b"))
    copilot = OllamaCopilot(mode="live")

    with pytest.raises(OllamaUnavailableError, match="ollama pull"):
        copilot.resolve_mode()


def test_auto_mode_uses_fallback_model_when_primary_is_missing(monkeypatch):
    """The whole run uses one model: the fallback when the primary isn't pulled."""
    monkeypatch.setattr(ollama_copilot.requests, "get", lambda *a, **k: tags_reply("llama3.2:3b"))
    copilot = OllamaCopilot(mode="auto")

    assert copilot.resolve_mode() == "live"
    assert copilot.active_model == "llama3.2:3b"
