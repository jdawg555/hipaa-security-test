from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any

from hipaa_audit.vendor_portal import QUESTIONS

_KEYWORD_HINTS: dict[str, list[str]] = {
    "soc2_or_iso": ["soc 2", "soc2", "iso 27001", "iso27001", "iso 27017"],
    "encryption_at_rest": ["encryption at rest", "aes-256", "encrypted at rest", "cmek", "kms"],
    "encryption_in_transit": ["tls 1.2", "tls 1.3", "encryption in transit", "https only", "in transit"],
    "mfa_enforced": ["mfa", "multi-factor", "2fa", "two-factor", "authenticator"],
    "access_logging": ["audit log", "access log", "logging retained", "siem", "cloudtrail"],
    "incident_notification": ["incident notification", "breach notification", "24 hour", "72 hour", "security incident"],
    "subprocessors_disclosed": ["subprocessor", "sub-processor", "third party list", "fourth party"],
    "data_retention_defined": ["data retention", "deletion policy", "retention period", "data destruction"],
}


def _keyword_suggest(text: str) -> dict[str, dict[str, Any]]:
    lowered = text.lower()
    suggestions: dict[str, dict[str, Any]] = {}
    for key, _label in QUESTIONS:
        hints = _KEYWORD_HINTS.get(key, [])
        hits = [h for h in hints if h in lowered]
        if hits:
            suggestions[key] = {
                "suggested": True,
                "confidence": "medium",
                "rationale": f"Mentioned: {hits[0]}",
            }
        else:
            suggestions[key] = {
                "suggested": None,
                "confidence": "low",
                "rationale": "No clear signal in pasted text",
            }
    return suggestions


def _llm_suggest(text: str, ai_cfg: dict[str, Any]) -> dict[str, dict[str, Any]] | None:
    api_key = os.environ.get(ai_cfg.get("api_key_env", "OPENAI_API_KEY"), "")
    base_url = ai_cfg.get("base_url", "https://api.openai.com/v1").rstrip("/")
    model = ai_cfg.get("model", "gpt-4o-mini")
    if not api_key or not text.strip():
        return None

    keys = [k for k, _ in QUESTIONS]
    prompt = (
        "You are a healthcare security analyst reviewing vendor documentation. "
        "Do NOT include PHI. Return ONLY JSON mapping each key to true, false, or null "
        f"for SIG-lite yes/no questions. Keys: {keys}. Text:\n{text[:12000]}"
    )
    payload = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
        }
    ).encode()
    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:  # noqa: S310
            body = json.loads(resp.read().decode())
        content = body["choices"][0]["message"]["content"]
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if not match:
            return None
        raw = json.loads(match.group())
    except Exception:  # noqa: BLE001
        return None

    suggestions: dict[str, dict[str, Any]] = {}
    for key, _ in QUESTIONS:
        val = raw.get(key)
        if val is True:
            suggestions[key] = {"suggested": True, "confidence": "high", "rationale": "LLM inference"}
        elif val is False:
            suggestions[key] = {"suggested": False, "confidence": "high", "rationale": "LLM inference"}
        else:
            suggestions[key] = {"suggested": None, "confidence": "low", "rationale": "LLM uncertain"}
    return suggestions


def suggest_sig_lite_responses(text: str, config: dict[str, Any]) -> dict[str, Any]:
    """Draft SIG-lite answers from vendor security text. Human review required."""
    ai = config.get("ai_assist", {})
    if not ai.get("enabled", False):
        return {"error": "AI assist disabled — enable in Settings", "suggestions": {}}
    if ai.get("disallow_phi", True) and _looks_like_phi(text):
        return {"error": "Text may contain PHI — remove identifiers before using AI assist", "suggestions": {}}

    suggestions = None
    if ai.get("use_llm", False):
        suggestions = _llm_suggest(text, ai)
    if not suggestions:
        suggestions = _keyword_suggest(text)
    return {
        "method": "llm" if ai.get("use_llm") and suggestions else "keywords",
        "suggestions": suggestions,
        "disclaimer": "Draft only — security team must verify before recording responses.",
    }


def _looks_like_phi(text: str) -> bool:
    if re.search(r"\b\d{3}-\d{2}-\d{4}\b", text):
        return True
    if re.search(r"\b(MRN|SSN|patient name|date of birth)\b", text, re.I):
        return True
    return False
