"""Optional LLM explanation layer.

Input: the structured `facts()` JSON only, never raw packets. Output is checked
before use: any cryptographic name, DH group, protocol version or score in the
text must appear in the input facts, otherwise the deterministic narrative is
used instead. The LLM never decides protocol values.
"""
from __future__ import annotations

import json
import logging
import re

from app.config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You write explanations for an IPsec VPN security analyzer.
You receive a JSON document produced by a deterministic packet parser and rule engine. It is the only source of truth.

Rules:
- Every statement about the observed configuration (protocols, algorithms, DH groups, modes, scores, findings) must come from the JSON. Never add, infer or correct a value.
- Fields whose value is "Unknown / Not observable" were not visible in the capture. Say so plainly; do not guess them.
- Each field has a "source": observed, inferred, observed-majority or unavailable. Keep inferred values clearly marked as inferred.
- The traffic category is a probabilistic prediction from packet sizes and timing, not decryption. Say so if you mention it.
- The score is the "Project Security Assessment Score", a project heuristic, not an official rating.
- Recommendations must follow from the findings listed in the JSON.

Write for two audiences: the executive summary for a non-technical manager (3-5 sentences), the technical explanation for a network security engineer."""

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "string"},
        "technical_explanation": {"type": "string"},
        "remediation": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["executive_summary", "technical_explanation", "remediation"],
    "additionalProperties": False,
}

# Tokens that name protocol values. Each one the model writes must exist in the facts.
_CLAIM_PATTERNS = [
    r"\bIKEv\d\b", r"\bDH\s?\d+\b", r"\b(?:MODP|ECP)-\d+\b", r"\bCurve(?:25519|448)\b",
    r"\bAES-\d+(?:-[A-Z]+(?:-\d+)?)?\b", r"\b3DES(?:-CBC)?\b", r"\bDES(?:-CBC)?\b", r"\bCHACHA20-POLY1305\b",
    r"\bHMAC-[A-Z0-9-]+\b", r"\bSHA-?(?:1|256|384|512)\b", r"\bMD5\b", r"\b(?:PRF|AUTH|INTEG)[-_][A-Z0-9_-]+\b",
    r"\b(?:CRYPTO|PROTO|SA|CONFIG|OBS|META)-\d{3}\b", r"\b\d{1,3}\s?/\s?100\b",
]


def ungrounded_claims(text: str, facts_json: str) -> list[str]:
    # IANA names say SHA2-256 where prose says SHA-256; accept both spellings.
    haystack = facts_json.upper().replace(" ", "")
    haystack += "|" + haystack.replace("SHA2-", "SHA-")
    claims = set()
    for pattern in _CLAIM_PATTERNS:
        for match in re.findall(pattern, text, flags=re.IGNORECASE):
            token = match.upper().replace(" ", "")
            if token.endswith("/100"):
                token = token[:-4]
                if f'"SECURITY_SCORE":{token}' not in haystack:
                    claims.add(match)
                continue
            # SHA256 and SHA-256 are the same claim; compare without hyphens as a fallback.
            if token not in haystack and token.replace("-", "") not in haystack.replace("-", ""):
                claims.add(match)
    return sorted(claims)


def llm_available() -> bool:
    return settings.llm_enabled and bool(settings.anthropic_api_key)


def generate(facts: dict) -> tuple[dict | None, str]:
    """Return (narrative, source note). narrative is None when the LLM is unavailable or its output is rejected."""
    if not llm_available():
        return None, "LLM disabled or ANTHROPIC_API_KEY not set"
    import anthropic

    facts_json = json.dumps(facts, indent=1, sort_keys=True)
    client = anthropic.Anthropic(api_key=settings.anthropic_api_key, timeout=120.0, max_retries=2)
    try:
        response = client.beta.messages.create(
            model=settings.llm_model,
            max_tokens=16000,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            system=SYSTEM_PROMPT,
            output_config={"effort": "medium", "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA}},
            messages=[{"role": "user", "content": f"Analyzer output:\n```json\n{facts_json}\n```"}],
        )
    except anthropic.APIConnectionError as exc:
        logger.warning("LLM unreachable: %s", exc)
        return None, "LLM unreachable"
    except anthropic.RateLimitError:
        return None, "LLM rate limited"
    except anthropic.APIStatusError as exc:
        logger.warning("LLM request failed (%s): %s", exc.status_code, exc.message)
        return None, f"LLM request failed ({exc.status_code})"

    if response.stop_reason == "refusal":
        return None, "LLM declined the request"
    if response.stop_reason == "max_tokens":
        return None, "LLM output was truncated"
    text = next((block.text for block in response.content if block.type == "text"), "")
    try:
        narrative = json.loads(text)
    except json.JSONDecodeError:
        return None, "LLM returned invalid JSON"
    combined = " ".join([narrative["executive_summary"], narrative["technical_explanation"], *narrative["remediation"]])
    if problems := ungrounded_claims(combined, facts_json):
        logger.warning("LLM narrative rejected; values not in analyzer output: %s", problems)
        return None, f"LLM output rejected: mentions values not in the analysis ({', '.join(problems[:5])})"
    return narrative, f"llm:{response.model}"
