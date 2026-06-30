"""Extracteur déterministe pour les preuves github-issues.

Conforme §7 : aucune I/O réseau (E-7.1), n'invente pas de versions (E-7.4),
spans systématiques bien que déterministe (DEVRAIT de E-4.3.3 appliqué).
"""
from __future__ import annotations

import json

from ..evidence_store import EvidenceStore
from ..models import CandidateFinding, Extraction, RawEvidence, new_finding_id

SEVERITY_LABELS = {
    "critical": "critical", "p0": "critical",
    "major": "major", "p1": "major", "high": "major",
    "minor": "minor", "p2": "minor", "low": "minor",
}
SECURITY_LABELS = {"security", "vulnerability", "cve"}
SYMPTOM_SEEDS = (
    "crash", "segfault", "hang", "deadlock", "regression", "incorrect",
    "corruption", "data loss", "memory leak", "race", "wrong result",
)


class GitHubIssuesExtractor:
    id = "github-issues-extractor"
    version = "0.1.0"
    deterministic = True

    def __init__(self, store: EvidenceStore, seq_start: int = 1):
        self.store = store
        self._seq = seq_start

    def accepts(self, ev: RawEvidence) -> bool:
        return ev.plugin_id == "github-issues" and ev.media_type == "application/json"

    def extract(self, ev: RawEvidence) -> list[CandidateFinding]:
        payload = self.store.get_payload(ev)        # E-7.1 : preuve archivée only
        issues = json.loads(payload)
        purl = ev.purl_hint or "pkg:generic/unknown"
        pkg_name = purl.removeprefix("pkg:github/").split("@")[0]
        findings: list[CandidateFinding] = []

        for i, issue in enumerate(issues):
            if "pull_request" in issue:             # PR ≠ bug report
                continue
            labels = {l["name"].lower() for l in issue.get("labels", [])}
            text = f"{issue.get('title','')}\n{issue.get('body') or ''}".lower()

            finding_class = "security" if labels & SECURITY_LABELS else "functional"
            severity = next(
                (SEVERITY_LABELS[l] for l in labels if l in SEVERITY_LABELS),
                "minor",
            )
            if issue["state"] == "open":
                status = "open"
            else:
                reason = issue.get("state_reason")
                status = {"completed": "fixed", "not_planned": "wontfix",
                          "duplicate": "duplicate"}.get(reason, "fixed")

            keywords = sorted({s for s in SYMPTOM_SEEDS if s in text})

            f = CandidateFinding(
                id=new_finding_id(self._seq),
                summary=issue.get("title", "")[:200],
                details=(issue.get("body") or "")[:4000],
                purl=purl,
                package_name=pkg_name,
                ecosystem="GitHub",
                finding_class=finding_class,
                functional_severity=severity,
                upstream_status=status,
                evidence_refs=[ev.content_hash],
                ranges=[],                          # E-7.4 : pas d'invention
                version_confidence=0.0,
                symptom_keywords=keywords,
                references=[{"type": "REPORT", "url": issue["html_url"]}],
                extraction=Extraction(
                    extractor_id=self.id,
                    extractor_version=self.version,
                    confidence=0.95,
                    source_spans=[{
                        "evidence": ev.content_hash,
                        "loc": f"issues[{i}].title|body",
                    }],
                ),
            )
            self._seq += 1
            findings.append(f)
        return findings
