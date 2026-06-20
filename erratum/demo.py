"""Démo bout-en-bout : SBOM(purl) → collecte → preuves → extraction → gate.

Usage : python -m erratum.demo pkg:github/<owner>/<repo> [workdir]
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from .evidence_store import EvidenceStore
from .extractors.github_issues_extractor import GitHubIssuesExtractor
from .gate import evaluate
from .plugins.github_issues import GitHubIssuesPlugin


def main() -> None:
    purl = sys.argv[1] if len(sys.argv) > 1 else "pkg:github/psf/requests"
    workdir = Path(sys.argv[2] if len(sys.argv) > 2 else "out")
    store = EvidenceStore(workdir / "evidence")
    findings_dir = workdir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    plugin = GitHubIssuesPlugin(store, per_page=15)
    plugin.manifest.validate()
    assert plugin.matches(purl), f"purl non couvert : {purl}"

    print(f"[collect] {purl} via {plugin.manifest.id}@{plugin.manifest.version}")
    result = plugin.collect(purl, cursor=None)
    for d in result.diagnostics:
        print(f"  [diag:{d.level}] {d.code}: {d.message}")
    print(
        f"  preuves archivées : {len(result.evidences)}"
        f" | curseur suivant : {result.next_cursor.state}"
    )

    extractor = GitHubIssuesExtractor(store)
    all_findings = []
    for ev in result.evidences:
        if extractor.accepts(ev):
            all_findings += extractor.extract(ev)
    print(f"[extract] findings candidats : {len(all_findings)}")

    decisions = []
    for f in all_findings:
        d = evaluate(
            f, deterministic=extractor.deterministic, tier=plugin.manifest.tier
        )
        f.ingestion_status = d.status
        decisions.append(d)
        (findings_dir / f"{f.id}.json").write_text(f.to_json(), encoding="utf-8")

    print(
        "[gate]   "
        + ", ".join(f"{k}={v}" for k, v in Counter(d.status for d in decisions).items())
    )
    print()
    for f, d in list(zip(all_findings, decisions))[:5]:
        kw = ",".join(f.symptom_keywords) or "-"
        print(
            f"  {f.id}  [{f.finding_class}/{f.functional_severity}/{f.upstream_status}]"
            f" → {d.status}\n      {f.summary[:80]}\n      mots-clés: {kw} | {d.rationale}"
        )

    audit = {
        "purl": purl,
        "plugin": {"id": plugin.manifest.id, "version": plugin.manifest.version},
        "extractor": {
            "id": extractor.id,
            "version": extractor.version,
            "deterministic": extractor.deterministic,
        },
        "decisions": [d.__dict__ for d in decisions],
    }
    (workdir / "audit.json").write_text(
        json.dumps(audit, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"\n[audit]  chaîne de décision écrite dans {workdir/'audit.json'}")


if __name__ == "__main__":
    main()
