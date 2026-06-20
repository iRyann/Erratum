"""Modèles de données — conformes à SPEC-collecte-plugins v0.2 (§4)."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class RawEvidence:
    """§4.2 — document source brut, immuable, adressé par hash."""
    evidence_id: str
    source_url: str
    fetched_at: str
    content_hash: str            # "sha256:<hex>"
    media_type: str
    payload_ref: str             # clé dans l'Evidence Store
    plugin_id: str
    plugin_version: str
    http_status: int | None = None
    headers_subset: dict[str, str] = field(default_factory=dict)
    purl_hint: str | None = None
    kind: str = "primary"        # primary | enrichment (§7.6)
    parent_evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Cursor:
    """§4.4 — état de synchronisation incrémentale, opaque pour l'orchestrateur."""
    plugin_id: str
    scope: str                   # purl
    state: dict[str, Any] = field(default_factory=dict)
    updated_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Extraction:
    extractor_id: str
    extractor_version: str
    confidence: float
    model_id: str | None = None
    prompt_version: str | None = None
    enrichment_used: bool = False
    source_spans: list[dict[str, str]] = field(default_factory=list)


@dataclass
class CandidateFinding:
    """§4.3 — OSV étendu via database_specific."""
    id: str
    summary: str
    details: str
    purl: str
    package_name: str
    ecosystem: str
    finding_class: str           # functional | security | documentation | performance
    functional_severity: str     # critical | major | minor | cosmetic
    upstream_status: str         # open | fixed | wontfix | duplicate | unknown
    evidence_refs: list[str]
    extraction: Extraction
    ranges: list[dict[str, Any]] = field(default_factory=list)
    version_confidence: float = 0.0
    workaround_available: bool = False
    workaround_summary: str | None = None
    symptom_keywords: list[str] = field(default_factory=list)
    references: list[dict[str, str]] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    ingestion_status: str = "candidate"
    ingestion_tier: str = "A"
    modified: str = field(default_factory=now_iso)
    published: str = field(default_factory=now_iso)

    def to_osv(self) -> dict[str, Any]:
        """Sérialisation OSV 1.6 + extensions. E-4.3.1 : sans database_specific,
        le document reste un OSV valide."""
        affected: dict[str, Any] = {
            "package": {
                "ecosystem": self.ecosystem,
                "name": self.package_name,
                "purl": self.purl,
            },
        }
        if self.ranges:
            affected["ranges"] = self.ranges
        affected["database_specific"] = {
            "version_confidence": self.version_confidence,
        }
        return {
            "schema_version": "1.6.0",
            "id": self.id,
            "modified": self.modified,
            "published": self.published,
            "summary": self.summary,
            "details": self.details,
            "aliases": self.aliases,
            "affected": [affected],
            "references": self.references,
            "database_specific": {
                "finding_class": self.finding_class,
                "functional_severity": self.functional_severity,
                "upstream_status": self.upstream_status,
                "workaround_available": self.workaround_available,
                "workaround_summary": self.workaround_summary,
                "symptom_keywords": self.symptom_keywords,
                "evidence_refs": self.evidence_refs,
                "extraction": asdict(self.extraction),
                "ingestion": {
                    "status": self.ingestion_status,
                    "tier": self.ingestion_tier,
                    "decided_by": None,
                    "decided_at": None,
                    "rationale": None,
                },
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.to_osv(), indent=2, ensure_ascii=False)


def new_finding_id(seq: int, year: int | None = None) -> str:
    y = year or datetime.now(timezone.utc).year
    return f"CFND-{y}-{seq:06d}"


def new_evidence_id() -> str:
    return str(uuid.uuid4())
