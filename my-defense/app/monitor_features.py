"""Feature extraction from raw v1 DefenseRequest JSON. No sentinel import, so it runs in the image."""

from __future__ import annotations

from typing import Any

from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import HashingVectorizer

TRUST_RANK = {
    "system_policy": 0,
    "authenticated_user": 1,
    "trusted_internal": 2,
    "untrusted_internal": 3,
    "untrusted_external": 4,
    "adversary_controlled": 5,
}
STATUS_CONSEQUENTIAL = {"ticket_update": {"closed", "resolved"}, "incident_update": {"closed"}}
NUMERIC_FEATURES = (
    "tool_not_allowed",
    "consequential",
    "is_confirmation_request",
    "external_recipient",
    "untrusted_items",
    "least_trusted_rank",
    "tool_named_in_untrusted",
    "memory_write",
    "respond",
)

_VECTORIZER = HashingVectorizer(n_features=2**12, alternate_sign=False, ngram_range=(1, 2), norm="l2")


def _target(request: dict[str, Any]) -> dict[str, Any]:
    action = request["candidate_action"]
    if action.get("type") == "request_confirmation" and action.get("confirmation_for"):
        return dict(action["confirmation_for"])
    return dict(action)


def action_text(request: dict[str, Any]) -> str:
    action = _target(request)
    args = action.get("arguments") or {}
    parts = [f"type_{action.get('type')}", f"tool_{action.get('tool')}"]
    parts += [f"arg_{key} {value}" for key, value in sorted(args.items())]
    if action.get("content"):
        parts.append(str(action["content"]))
    return " ".join(parts)[:4000]


def numeric_features(request: dict[str, Any]) -> list[float]:
    action = _target(request)
    policy = request.get("policy_context") or {}
    tool = action.get("tool")
    args = action.get("arguments") or {}
    trust = {r["id"]: r["provenance"]["trust_level"] for r in request.get("provenance", [])}
    untrusted = [
        item
        for item in request.get("conversation", [])
        if any(TRUST_RANK.get(trust.get(pid, ""), 0) >= 3 for pid in item.get("provenance_ids", []))
    ]
    ranks = [TRUST_RANK.get(level, 0) for level in trust.values()]
    status = args.get("status")
    internal = [d.lower() for d in policy.get("internal_email_domains", [])]
    recipient = str(args.get("to", "")).lower()
    return [
        float(action.get("type") == "tool_call" and tool not in policy.get("allowed_tools", [])),
        float(
            tool in policy.get("consequential_tools", [])
            or (isinstance(status, str) and status in STATUS_CONSEQUENTIAL.get(str(tool), set()))
        ),
        float(request["candidate_action"].get("type") == "request_confirmation"),
        float(bool(recipient) and not any(recipient.endswith("@" + d) for d in internal)),
        min(len(untrusted), 5) / 5,
        (max(ranks) if ranks else 1) / 5,
        float(bool(tool) and any(str(tool) in item.get("content", "") for item in untrusted)),
        float(action.get("type") == "memory_write"),
        float(action.get("type") == "respond"),
    ]


def featurize(requests: list[dict[str, Any]]) -> csr_matrix:
    text = _VECTORIZER.transform([action_text(r) for r in requests])
    numeric = csr_matrix([numeric_features(r) for r in requests])
    return hstack([text, numeric * 3.0]).tocsr()
