"""Optional, validated LLM review for audit plans.

The local evidence engine remains authoritative. This module can ask Groq or
Gemini to review a generated plan, but accepts a response only when it is a
strictly valid replacement with the same contract-level status and steps.
"""

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


def _load_local_env() -> None:
    """Load the repository-root .env without overwriting real env values."""
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    try:
        with open(env_path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, value = line.split("=", 1)
                name = name.strip()
                value = value.strip().strip("\"'")
                if name and name not in os.environ:
                    os.environ[name] = value
    except OSError:
        pass


_load_local_env()


ALLOWED_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
ALLOWED_PHASES = {"FINDING", "REMEDIATION", "VERIFICATION"}
ALLOWED_OPERATIONS = {
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
}
ALLOWED_STATES = {
    "PRESENT",
    "ACTIVE",
    "DISABLED",
    "BLOCKED",
    "ABSENT",
    "REDACTED",
    "ANONYMIZED",
}


def _redact(text: str) -> str:
    """Remove common direct identifiers before sending text to a provider."""
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[email]", text or "")
    text = re.sub(r"\+?\d[\d\s().-]{7,}\d", "[phone]", text)
    return text


def _validate_plan(candidate: Any, original_status: str) -> Optional[Tuple[str, List[Dict[str, Any]]]]:
    if not isinstance(candidate, dict):
        return None
    status = candidate.get("deletion_status")
    steps = candidate.get("steps")
    if status not in ALLOWED_STATUSES or status != original_status or not isinstance(steps, list):
        return None
    if status == "NOT_APPLICABLE" and steps:
        return None

    previous_phase = 0
    normalized = []
    phase_order = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
    for number, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            return None
        required = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
        if set(step) != required or step["step_no"] != number:
            return None
        if step["phase"] not in ALLOWED_PHASES or step["operation"] not in ALLOWED_OPERATIONS:
            return None
        if step["state"] not in ALLOWED_STATES or not all(isinstance(step[k], str) for k in required - {"step_no"}):
            return None
        phase = phase_order[step["phase"]]
        if phase < previous_phase:
            return None
        previous_phase = phase
        normalized.append(step)
    return status, normalized


class AIReviewer:
    """Provider-neutral reviewer with explicit opt-in and safe fallback."""

    def __init__(self) -> None:
        self.provider = os.getenv("AUDIT_AI_PROVIDER", "").strip().lower()
        self.timeout = float(os.getenv("AUDIT_AI_TIMEOUT_SECONDS", "20"))
        self.groq_model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
        self.gemini_model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self.calls = 0
        self.failures = 0

    @property
    def enabled(self) -> bool:
        return self.provider in {"groq", "gemini", "both"}

    def review(
        self,
        request: Dict[str, str],
        status: str,
        steps: List[Dict[str, Any]],
        evidence_summary: List[Dict[str, Any]],
    ) -> Tuple[str, List[Dict[str, Any]]]:
        if not self.enabled:
            return status, steps

        prompt = self._prompt(request, status, steps, evidence_summary)
        providers = ["groq", "gemini"] if self.provider == "both" else [self.provider]
        for provider in providers:
            try:
                raw = self._call(provider, prompt)
                self.calls += 1
                candidate = self._extract_json(raw)
                validated = _validate_plan(candidate, status)
                if validated is not None:
                    return validated
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                self.failures += 1
        return status, steps

    def _prompt(
        self,
        request: Dict[str, str],
        status: str,
        steps: List[Dict[str, Any]],
        evidence_summary: List[Dict[str, Any]],
    ) -> str:
        payload = {
            "case_id": request.get("case_id", ""),
            "audit_at": request.get("audit_at", ""),
            "request_text": _redact(request.get("request_text", "")),
            "current_status": status,
            "current_steps": steps,
            "evidence_summary": evidence_summary,
        }
        return (
            "Review this deletion-audit plan using only the supplied facts. "
            "Keep the current deletion_status unchanged. Return JSON only with "
            "exactly {\"deletion_status\": string, \"steps\": array}. Preserve "
            "the step object keys, allowed operations/states, evidence IDs, and "
            "step numbering. Do not invent resources or evidence. If no safe "
            "improvement is supported, return the current plan unchanged.\n\n"
            + json.dumps(payload, separators=(",", ":"))
        )

    def _call(self, provider: str, prompt: str) -> str:
        if provider == "groq":
            key = os.getenv("GROQ_API_KEY")
            if not key:
                raise ValueError("GROQ_API_KEY is not configured")
            body = {
                "model": self.groq_model,
                "temperature": 0,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": "You are a precise audit-plan reviewer."},
                    {"role": "user", "content": prompt},
                ],
            }
            request = urllib.request.Request(
                "https://api.groq.com/openai/v1/chat/completions",
                data=json.dumps(body).encode("utf-8"),
                headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))["choices"][0]["message"]["content"]

        if provider == "gemini":
            key = os.getenv("GEMINI_API_KEY")
            if not key:
                raise ValueError("GEMINI_API_KEY is not configured")
            body = {
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0, "responseMimeType": "application/json"},
            }
            url = (
                "https://generativelanguage.googleapis.com/v1beta/models/"
                + self.gemini_model
                + ":generateContent?key="
                + key
            )
            request = urllib.request.Request(
                url,
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))["candidates"][0]["content"]["parts"][0]["text"]
        raise ValueError("Unsupported AI provider")

    @staticmethod
    def _extract_json(raw: str) -> Dict[str, Any]:
        text = raw.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE)
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ValueError("Provider response was not a JSON object")
        return parsed
