"""Evidence Store — §4.2 : archivage immuable, adressé par contenu (sha256).

Implémentation fichier : objects/<hex> pour les payloads bruts,
evidence.jsonl en append-only pour les métadonnées (E-10.3).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .models import RawEvidence, new_evidence_id, now_iso


class EvidenceStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        (self.root / "objects").mkdir(parents=True, exist_ok=True)
        self.index = self.root / "evidence.jsonl"

    def put(
        self,
        payload: bytes,
        *,
        source_url: str,
        media_type: str,
        plugin_id: str,
        plugin_version: str,
        http_status: int | None = None,
        headers_subset: dict[str, str] | None = None,
        purl_hint: str | None = None,
        kind: str = "primary",
        parent_evidence: str | None = None,
    ) -> RawEvidence:
        """E-4.2.1 : le payload est archivé tel que reçu, avant tout parsing."""
        digest = hashlib.sha256(payload).hexdigest()
        obj = self.root / "objects" / digest
        if not obj.exists():                 # idempotence par contenu (E-4.4.1)
            obj.write_bytes(payload)
        ev = RawEvidence(
            evidence_id=new_evidence_id(),
            source_url=source_url,
            fetched_at=now_iso(),
            content_hash=f"sha256:{digest}",
            media_type=media_type,
            payload_ref=str(obj.relative_to(self.root)),
            plugin_id=plugin_id,
            plugin_version=plugin_version,
            http_status=http_status,
            headers_subset=headers_subset or {},
            purl_hint=purl_hint,
            kind=kind,
            parent_evidence=parent_evidence,
        )
        with self.index.open("a", encoding="utf-8") as f:
            f.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")
        return ev

    def get_payload(self, evidence: RawEvidence) -> bytes:
        """E-7.1 : l'extraction lit ici, jamais sur le réseau."""
        return (self.root / evidence.payload_ref).read_bytes()
