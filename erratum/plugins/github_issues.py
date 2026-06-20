"""Plugin Tier A — GitHub Issues.

Collecte les issues d'un dépôt identifié par un purl pkg:github/<owner>/<repo>.
Conforme §6 : collecte seulement, archivage brut, curseur incrémental (since),
aucune extraction ici (E-6.3).
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request

from ..evidence_store import EvidenceStore
from ..models import Cursor, now_iso
from ..plugin_api import CollectResult, Diag, PluginManifest

MANIFEST = PluginManifest(
    id="github-issues",
    version="0.1.0",
    tier="A",
    display_name="GitHub Issues",
    collection_mode="api",
    purl_types=("github",),
    allowed_domains=("api.github.com",),
    requests_per_minute=20,
)

USER_AGENT = "cots-findings-prototype/0.1 (+research)"  # E-6.6


def _parse_purl(purl: str) -> tuple[str, str]:
    # pkg:github/owner/repo[@version]
    body = purl.removeprefix("pkg:github/")
    body = body.split("@", 1)[0]
    owner, repo = body.split("/", 1)
    return owner, repo


class GitHubIssuesPlugin:
    manifest = MANIFEST

    def __init__(self, store: EvidenceStore, per_page: int = 20):
        self.store = store
        self.per_page = per_page

    def matches(self, purl: str) -> bool:
        return purl.startswith("pkg:github/")

    def collect(self, purl: str, cursor: Cursor | None) -> CollectResult:
        owner, repo = _parse_purl(purl)
        state = dict(cursor.state) if cursor else {}
        page = int(state.get("page", 1))
        since = state.get("since")

        params = {
            "state": "all",
            "labels": "bug",            # réduction de bruit côté Tier A
            "per_page": str(self.per_page),
            "page": str(page),
            "sort": "updated",
            "direction": "asc",
        }
        if since:
            params["since"] = since
        url = (
            f"https://api.github.com/repos/{owner}/{repo}/issues?"
            + urllib.parse.urlencode(params)
        )

        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github+json",
        })
        diagnostics: list[Diag] = []
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = resp.read()
                status = resp.status
                headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() in ("etag", "last-modified", "x-ratelimit-remaining")
                }
        except urllib.error.HTTPError as e:          # E-6.5
            code = "SOURCE_GONE" if e.code == 404 else "HTTP_ERROR"
            diagnostics.append(Diag("error", code, f"{e.code} sur {url}", scope=purl))
            return CollectResult([], cursor or Cursor(self.manifest.id, purl), True, diagnostics)

        # E-4.2.1 : archivage du brut avant tout parsing
        ev = self.store.put(
            payload,
            source_url=url,
            media_type="application/json",
            plugin_id=self.manifest.id,
            plugin_version=self.manifest.version,
            http_status=status,
            headers_subset=headers,
            purl_hint=purl,
        )

        items = json.loads(payload)
        exhausted = len(items) < self.per_page
        next_state = {"page": 1 if exhausted else page + 1}
        if exhausted and items:
            # prochain run incrémental : reprendre après la dernière maj vue
            next_state["since"] = max(i["updated_at"] for i in items)
        elif since:
            next_state["since"] = since

        next_cursor = Cursor(
            plugin_id=self.manifest.id, scope=purl,
            state=next_state, updated_at=now_iso(),
        )
        return CollectResult([ev], next_cursor, exhausted, diagnostics)
