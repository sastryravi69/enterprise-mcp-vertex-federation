"""Zero-overhead pre-inference LLM prompt router (Gemini 1.5 Flash vs Gemini 1.5 Pro)."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Literal

from ..config import MODEL_CATALOG, ModelTierSpec

TierName = Literal["flash", "pro"]

SIMPLE_LEAD_RE = re.compile(
    r"^\s*(?:get|fetch|list|show|find|lookup|check|count|what\s+is|what\s+are|who\s+owns|how\s+many|retrieve|display)\b",
    re.IGNORECASE,
)

SIMPLE_TERMS = (
    "status of",
    "summary for",
    "list ",
    "open tickets",
    "sla status",
    "deal stage",
    "renewal date",
    "top ",
    "audit trail",
    "p1 tickets",
    "pipeline kpis",
)

COMPLEX_STRONG_TERMS = (
    "why ",
    "root cause",
    "trade-off",
    "tradeoff",
    "strategy",
    "strategic",
    "propose",
    "recommend",
    "forecast",
    "correlate",
    "correlation",
    "optimize",
    "margin",
    "synthesize",
    "compare ",
    "vs ",
    "versus",
    "prioritize",
    "remediate",
    "remediation plan",
    "negotiation plan",
    "churn risk",
    "impact of",
    "scenario",
    "counter-offer",
    "executive brief",
    "multi-step",
    "cross-region",
)

CROSS_DOMAIN_SIGNALS = {
    "commercial": ("deal", "discount", "margin", "pipeline", "renewal", "acv", "revenue", "pricing"),
    "support": ("ticket", "sla", "breach", "outage", "incident", "escalation", "p1", "latency"),
    "governance": ("compliance", "audit", "privacy", "residency", "gdpr", "rbi", "hipaa", "risk"),
}


@dataclass(frozen=True)
class RoutingDecision:
    """Explainable prompt routing output."""

    prompt: str
    selected_tier: TierName
    model_id: str
    display_name: str
    complexity_score: float
    confidence: float
    task_category: str
    reasons: list[str]
    classifier_latency_ms: float


class PromptRouter:
    """Intercepts prompts and routes simple retrieval to Flash, complex reasoning to Pro."""

    def __init__(
        self,
        pro_threshold: float = 0.50,
        catalog: dict[str, ModelTierSpec] | None = None,
    ) -> None:
        self.pro_threshold = pro_threshold
        self.catalog = catalog or MODEL_CATALOG

    def route(self, prompt: str) -> RoutingDecision:
        t0 = time.perf_counter()
        text = prompt.strip()
        lower = text.lower()
        words = re.findall(r"\b\w+\b", lower)
        word_count = len(words)

        score = 0.30  # Neutral-low baseline biased toward fast retrieval unless reasoning signals appear
        reasons: list[str] = []

        # 1. Strong reasoning / synthesis cues
        matched_complex = [term.strip() for term in COMPLEX_STRONG_TERMS if term in lower]
        if matched_complex:
            boost = min(0.55, 0.24 + 0.10 * (len(matched_complex) - 1))
            score += boost
            reasons.append(f"Reasoning markers detected: {', '.join(matched_complex[:4])}")

        # 2. Cross-domain correlation (joining commercial + support + governance in one reasoning query)
        domains_hit = [
            domain
            for domain, keywords in CROSS_DOMAIN_SIGNALS.items()
            if any(kw in lower for kw in keywords)
        ]
        if len(domains_hit) >= 2:
            score += 0.22
            reasons.append(f"Cross-domain synthesis across {', '.join(domains_hit)}")

        # 3. Multi-clause / multi-question complexity
        clause_markers = sum(
            lower.count(sep) for sep in (" and ", " while ", " balancing ", " given ", "?")
        )
        if clause_markers >= 3 or lower.count("?") >= 2:
            score += 0.14
            reasons.append("Multi-clause analytical prompt structure")

        # 4. Prompt length heuristic
        if word_count >= 26:
            score += 0.12
            reasons.append(f"Extended prompt context ({word_count} words)")
        elif word_count <= 14 and not matched_complex:
            score -= 0.10
            reasons.append(f"Concise lookup structure ({word_count} words)")

        # 5. Simple retrieval cues (apply discount only when strong complex reasoning isn't dominant)
        is_simple_lead = bool(SIMPLE_LEAD_RE.search(text))
        matched_simple = [term.strip() for term in SIMPLE_TERMS if term in lower]
        if is_simple_lead and len(matched_complex) == 0:
            score -= 0.18
            reasons.append("Direct retrieval/lookup verb prefix")
        if matched_simple and len(matched_complex) == 0:
            score -= 0.10
            reasons.append(f"Retrieval pattern: {', '.join(matched_simple[:2])}")

        bounded_score = max(0.02, min(0.99, round(score, 3)))
        selected_tier: TierName = "pro" if bounded_score >= self.pro_threshold else "flash"
        spec = self.catalog[selected_tier]

        distance = abs(bounded_score - self.pro_threshold)
        confidence = round(min(0.99, 0.62 + distance * 0.8), 3)

        if selected_tier == "pro":
            category = "multi_hop_synthesis" if len(domains_hit) >= 2 else "complex_reasoning"
        else:
            category = "status_check" if any(k in lower for k in ("status", "sla", "breach", "open")) else "simple_retrieval"

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        if not reasons:
            reasons.append("Default low-complexity retrieval profile")

        return RoutingDecision(
            prompt=prompt,
            selected_tier=selected_tier,
            model_id=spec.model_id,
            display_name=spec.display_name,
            complexity_score=bounded_score,
            confidence=confidence,
            task_category=category,
            reasons=reasons,
            classifier_latency_ms=elapsed_ms,
        )

