"""Gate de validation — §8 de la spec."""
from __future__ import annotations

from dataclasses import dataclass

from .models import CandidateFinding


@dataclass(frozen=True)
class GateConfig:
    auto_confidence: float = 0.90
    review_confidence: float = 0.60
    version_confidence: float = 0.90


@dataclass(frozen=True)
class GateDecision:
    finding_id: str
    status: str          # ingested_auto | review_high | review_normal | rejected
    rationale: str


def evaluate(f: CandidateFinding, cfg: GateConfig = GateConfig(),
             *, deterministic: bool, tier: str,
             dedup_ambiguous: bool = False) -> GateDecision:
    conf = f.extraction.confidence

    if conf < cfg.review_confidence:
        return GateDecision(f.id, "rejected", f"confiance {conf:.2f} < {cfg.review_confidence}")

    auto = (
        tier == "A"
        and deterministic                       # E-8.3
        and bool(f.ranges)
        and f.version_confidence >= cfg.version_confidence
        and conf >= cfg.auto_confidence
        and not dedup_ambiguous
    )
    if auto:
        return GateDecision(f.id, "ingested_auto", "toutes conditions §8 satisfaites")

    if tier == "A":
        why = []
        if not f.ranges:
            why.append("ranges vides")
        if not deterministic:
            why.append("extraction non déterministe (E-8.3)")
        if dedup_ambiguous:
            why.append("dédup ambiguë (E-9.2)")
        return GateDecision(f.id, "review_high", "tier A mais " + ", ".join(why or ["confiance insuffisante"]))

    return GateDecision(f.id, "review_normal", f"tier {tier}, confiance {conf:.2f}")
