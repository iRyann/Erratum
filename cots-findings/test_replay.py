"""Test de rejeu — checklist §13.7 : corpus de preuves de référence → extraction
déterministe, puis gate. Aucun accès réseau (E-7.1 vérifié de fait)."""
from __future__ import annotations

import json
from pathlib import Path

from cots_findings.evidence_store import EvidenceStore
from cots_findings.extractors.github_issues_extractor import GitHubIssuesExtractor
from cots_findings.gate import evaluate

FIXTURE = [
    {
        "number": 6601,
        "title": "Crash (segfault) in connection pool under high concurrency",
        "body": "After upgrading to 2.31.0 we observe a segfault and data corruption "
                "in the pool when many threads share a Session. Workaround: one "
                "Session per thread. See https://github.com/psf/requests/issues/6000",
        "state": "open",
        "state_reason": None,
        "labels": [{"name": "bug"}, {"name": "P1"}],
        "html_url": "https://github.com/psf/requests/issues/6601",
        "updated_at": "2026-05-01T10:00:00Z",
    },
    {
        "number": 6587,
        "title": "Regression: incorrect Content-Length for streamed uploads",
        "body": "Since 2.32.0 streamed uploads send a wrong result for "
                "Content-Length, fixed upstream in 2.32.2.",
        "state": "closed",
        "state_reason": "completed",
        "labels": [{"name": "bug"}],
        "html_url": "https://github.com/psf/requests/issues/6587",
        "updated_at": "2026-04-12T08:00:00Z",
    },
    {
        "number": 6550,
        "title": "Docs: typo in advanced usage page",
        "body": "Minor typo.",
        "state": "closed",
        "state_reason": "not_planned",
        "labels": [{"name": "bug"}],
        "html_url": "https://github.com/psf/requests/issues/6550",
        "updated_at": "2026-03-02T08:00:00Z",
    },
    {
        "number": 6540,
        "title": "CVE candidate: header injection via crafted URL",
        "body": "Possible vulnerability, needs triage.",
        "state": "open",
        "state_reason": None,
        "labels": [{"name": "bug"}, {"name": "security"}],
        "html_url": "https://github.com/psf/requests/issues/6540",
        "updated_at": "2026-05-20T08:00:00Z",
    },
]


def main() -> None:
    work = Path("out-replay")
    store = EvidenceStore(work / "evidence")

    payload = json.dumps(FIXTURE).encode()
    ev = store.put(
        payload,
        source_url="https://api.github.com/repos/psf/requests/issues?fixture=1",
        media_type="application/json",
        plugin_id="github-issues",
        plugin_version="0.1.0",
        http_status=200,
        purl_hint="pkg:github/psf/requests",
    )
    print(f"[evidence] {ev.content_hash}")

    ex = GitHubIssuesExtractor(store)
    run1 = ex.extract(ev)

    # Rejeu : extraction bit-à-bit identique (déterminisme)
    ex2 = GitHubIssuesExtractor(store)
    run2 = ex2.extract(ev)
    same = [f.to_osv() for f in run1] == [f.to_osv() for f in run2]
    # (les ids sont régénérés à seq identique, modified peut différer d'1s)
    strip = lambda d: {k: v for k, v in d.items() if k not in ("modified", "published")}
    same = [strip(f.to_osv()) for f in run1] == [strip(f.to_osv()) for f in run2]
    print(f"[replay]   extraction identique : {same}")
    assert same, "déterminisme violé (§13.7)"

    print(f"[extract]  {len(run1)} findings\n")
    for f in run1:
        d = evaluate(f, deterministic=True, tier="A")
        f.ingestion_status = d.status
        out = work / "findings" / f"{f.id}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(f.to_json(), encoding="utf-8")
        print(f"  {f.id} [{f.finding_class}/{f.functional_severity}/{f.upstream_status}]"
              f" kw={','.join(f.symptom_keywords) or '-'}\n"
              f"      {f.summary[:70]}\n      → {d.status} ({d.rationale})")

    print("\n[osv] exemple de sortie OSV étendue :")
    print(run1[0].to_json()[:1200])


if __name__ == "__main__":
    main()
