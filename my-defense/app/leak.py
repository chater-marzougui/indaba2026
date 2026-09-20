"""Generic sensitive-content leak detection.

The defense never sees ground-truth canary values (that would be scenario-specific
hard-coding). Instead it treats any conversation content whose provenance carries
``confidential``/``restricted`` sensitivity as a *potential* secret, extracts candidate
sensitive spans from it, and checks whether the candidate action's outgoing text contains
those spans -- directly or through the same textual transforms attackers use to dodge
plain-substring filters (spacing, base64, hex, rot13, reversal).
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re

SENSITIVE_SENSITIVITY = {"confidential", "restricted"}
_NON_ALNUM = re.compile(r"[^a-z0-9]")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_TOKEN = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{7,}")  # secret-shaped: id/token-like, len >= 8
MIN_SPAN_CHARS = 24  # window size for chunked whole-document overlap
WINDOW_STEP = 12


def normalize(text: str) -> str:
    return _NON_ALNUM.sub("", text.lower())


def _decode_b64(text: str) -> str:
    out = []
    for token in _B64_TOKEN.findall(text):
        padded = token + "=" * (-len(token) % 4)
        try:
            out.append(base64.b64decode(padded, validate=True).decode("utf-8", "ignore"))
        except (binascii.Error, ValueError):
            continue
    return "\n".join(out)


def _decode_hex(text: str) -> str:
    out = []
    for token in _HEX_TOKEN.findall(text):
        try:
            out.append(bytes.fromhex(token).decode("utf-8", "ignore"))
        except ValueError:
            continue
    return "\n".join(out)


def text_variants(text: str) -> list[str]:
    text = text[:200_000]
    return [text, _decode_b64(text), _decode_hex(text), codecs.decode(text, "rot13"), text[::-1]]


def sensitive_spans(sensitive_texts: list[str]) -> list[str]:
    """Candidate secret substrings pulled out of confidential/restricted content."""
    spans: set[str] = set()
    for text in sensitive_texts:
        spans.update(m.group(0) for m in _TOKEN.finditer(text))
        norm = normalize(text)
        for start in range(0, max(1, len(norm) - MIN_SPAN_CHARS + 1), WINDOW_STEP):
            spans.add(norm[start : start + MIN_SPAN_CHARS])
    return [s for s in spans if len(s) >= 8]


def leaks(candidate_text: str, sensitive_texts: list[str]) -> bool:
    if not candidate_text or not sensitive_texts:
        return False
    spans = sensitive_spans(sensitive_texts)
    if not spans:
        return False
    haystacks = [normalize(v) for v in text_variants(candidate_text)]
    return any(span in haystack for span in spans for haystack in haystacks if haystack)
