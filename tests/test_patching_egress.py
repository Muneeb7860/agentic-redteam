"""Egress redaction regression tests.

Found by driving the GENERATED middleware directly rather than trusting the
unit suite: a live API key passed through egress sanitization untouched while
the credit card beside it was correctly redacted.
"""
from agentic_redteam.patching.guardrails import sanitize_egress


def _clean(text: str) -> str:
    out = sanitize_egress(text)
    return out[0] if isinstance(out, tuple) else out


def test_openai_project_key_is_redacted():
    """The regression. `\\bsk-[a-zA-Z0-9]{20,}\\b` stops at the first hyphen, so
    it matched sk-abc123... but NOT sk-proj-..., which is OpenAI's current
    project-key format. A live key leaked straight through the patch."""
    key = "sk-proj-abc123XYZ456def789GHI012jkl"
    assert key not in _clean(f"your key is {key}")


def test_hyphen_and_underscore_key_forms_are_both_redacted():
    for key in ("sk-" + "live-4eC39HqLyjWDarjtT1zdp7dc",
                "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dcABCD",
                "sk-abc123def456ghi789jkl012"):
        assert key not in _clean(f"key: {key}"), key


def test_other_provider_tokens_are_redacted():
    for key in ("AKIAIOSFODNN7EXAMPLE",
                "ghp_abcdefghij1234567890ABCDEFGHIJ12"):
        assert key not in _clean(f"token: {key}"), key


def test_credit_card_still_redacted():
    """Guard against the widened key pattern disturbing existing redaction."""
    assert "4012888888881881" not in _clean("card 4012888888881881 on file")


def test_ordinary_hyphenated_text_is_not_touched():
    """The widened pattern must not start eating normal prose. A redactor that
    mangles legitimate output gets switched off, and then it protects nothing."""
    for benign in ("please ask-someone about this",
                   "task-management-system-v2-final",
                   "risk-assessment-framework-v3-draft",
                   "Our support desk-team handles this"):
        assert _clean(benign) == benign, benign
