# Spécification — Architecture de collecte par plugins

**Projet :** Agrégateur de bugs fonctionnels COTS (nom de code : *cots-findings*)
**Version :** 0.2 (draft)
**Statut :** Proposition
**Date :** 2026-06-10
**Changements 0.2 :** ajout du mode d'enrichissement réseau optionnel des
extracteurs (§7.6), assouplissement de E-7.1, impacts sur §10, §11, §13.

---

## 1. Objet et périmètre

Ce document spécifie l'architecture de collecte de l'agrégateur : le contrat des
plugins de source, le modèle de données des preuves et des findings candidats,
le contrat des extracteurs, la gate de validation pour l'ingestion, ainsi que
les exigences de traçabilité et de sécurité.

**Dans le périmètre :** collecte multi-sources, extraction, normalisation,
déduplication, validation, archivage des preuves.

**Hors périmètre (specs ultérieures) :** workflow de qualification d'impact
(VEX/CSAF), interface utilisateur, export vers agrégateurs tiers (GUAC,
Dependency-Track), gestion des SBOM en entrée.

### 1.1 Références normatives et techniques

| Réf. | Document |
|------|----------|
| [OSV] | OSV Schema, OpenSSF — format canonique de finding (https://ossf.github.io/osv-schema/) |
| [PURL] | Package URL specification |
| [CSAF] | Common Security Advisory Framework v2, OASIS — format cible de la qualification |
| [AMC-20-189] | EASA AMC 20-189 — Management of Open Problem Reports |
| [SEMVER] | Semantic Versioning 2.0.0 |
| [RFC2119] | Mots-clés d'exigence |

### 1.2 Conventions

Les mots-clés **DOIT**, **NE DOIT PAS**, **DEVRAIT**, **PEUT** sont à
interpréter au sens de [RFC2119] (MUST, MUST NOT, SHOULD, MAY).

---

## 2. Terminologie

| Terme | Définition |
|-------|------------|
| **COTS** | Composant logiciel tiers (commercial ou open source) référencé dans le SBOM du logiciel critique. |
| **Source** | Canal de publication d'informations de bugs (tracker d'issues, changelog, page web vendeur, mailing list…). |
| **Plugin** | Module logiciel implémentant le contrat `SourcePlugin` pour une famille de sources. |
| **Preuve (`RawEvidence`)** | Document brut, immuable, horodaté et haché, collecté depuis une source. |
| **Extracteur** | Module transformant une preuve en zéro ou plusieurs findings candidats. |
| **Finding candidat (`CandidateFinding`)** | Bug structuré au format OSV étendu, non encore validé. |
| **Finding ingéré** | Finding ayant passé la gate de validation (automatiquement ou par revue humaine). |
| **Curseur (`Cursor`)** | État de synchronisation incrémentale d'un plugin pour un couple (source, composant). |
| **Tier** | Classe de fiabilité/structuration d'une source : A (API structurée), B (semi-structuré), C (non structuré). |

---

## 3. Vue d'ensemble

```
SBOM (watchlist purl)
   │
   ▼
Orchestrateur ── scheduling, curseurs, rate limiting
   │
   ▼
SourcePlugin.collect()  ──────►  Evidence Store (immuable, adressé par hash)
   │                                  │
   ▼                                  │ (rejouable)
Extractor.extract()  ◄────────────────┘
   │
   ▼
CandidateFinding
   │
   ▼
Gate de validation ──► auto-ingestion │ file de revue humaine │ rejet
   │
   ▼
Base de findings (OSV étendu) ──► [hors périmètre] qualification VEX/CSAF
```

Invariant central : **aucun finding sans preuve**. Tout `CandidateFinding`
DOIT référencer au moins une `RawEvidence` archivée. L'extraction DOIT être
rejouable à partir des seules preuves archivées (sans nouvel accès réseau).

---

## 4. Modèle de données

### 4.1 Identifiants

* **Composants :** identifiés par [PURL]. Pour les COTS sans écosystème de
  packaging (binaires vendeur, bibliothèques C/C++), le purl générique
  `pkg:generic/<vendor>/<name>@<version>` DOIT être utilisé, complété si
  possible par des plages de commits Git (conformément à [OSV]).
* **Findings :** identifiant au format `CFND-<AAAA>-<NNNNNN>`
  (préfixe de base conforme à la convention OSV `<DB>-<ENTRYID>`).
* **Preuves :** adressées par contenu — `sha256` du payload brut.

### 4.2 `RawEvidence`

Représente un document source brut. Immuable après écriture.

```json
{
  "$id": "https://cots-findings.example/schemas/raw-evidence-1.0.json",
  "type": "object",
  "required": ["evidence_id", "source_url", "fetched_at", "content_hash",
               "media_type", "payload_ref", "plugin_id", "plugin_version"],
  "properties": {
    "evidence_id":    { "type": "string", "description": "UUIDv7" },
    "source_url":     { "type": "string", "format": "uri" },
    "fetched_at":     { "type": "string", "format": "date-time" },
    "content_hash":   { "type": "string", "pattern": "^sha256:[a-f0-9]{64}$" },
    "media_type":     { "enum": ["application/json", "text/html",
                                  "application/pdf", "text/plain", "text/markdown"] },
    "payload_ref":    { "type": "string", "description": "Clé dans l'Evidence Store" },
    "plugin_id":      { "type": "string" },
    "plugin_version": { "type": "string", "description": "SemVer" },
    "http_status":    { "type": "integer" },
    "headers_subset": { "type": "object", "description": "ETag, Last-Modified si présents" },
    "purl_hint":      { "type": "string", "description": "purl ayant motivé la collecte" }
  }
}
```

Exigences :

* E-4.2.1 — Le payload brut DOIT être archivé tel que reçu (avant tout
  parsing), compressé au plus, jamais modifié.
* E-4.2.2 — Une preuve NE DOIT PAS être supprimée tant qu'un finding ingéré
  la référence (rétention pilotée par la politique d'audit du projet).
* E-4.2.3 — Pour le HTML, le plugin DEVRAIT archiver également un rendu
  texte stabilisé (post-DOM) en preuve secondaire liée.

### 4.3 `CandidateFinding` — OSV étendu

Le format de base est [OSV] v1.x. Les champs spécifiques sont portés par
`database_specific` (au niveau racine et au niveau `affected[]`), garantissant
la compatibilité avec les consommateurs OSV standard (E-4.3.1 : un
`CandidateFinding` débarrassé de `database_specific` DOIT rester un document
OSV valide).

```json
{
  "schema_version": "1.6.0",
  "id": "CFND-2026-000042",
  "modified": "2026-06-10T09:00:00Z",
  "published": "2026-06-10T09:00:00Z",
  "summary": "Résultat incorrect de l'allocateur temps-réel sous contention",
  "details": "…",
  "aliases": [],
  "affected": [{
    "package": { "ecosystem": "Generic", "name": "vendorx/rtalloc", "purl": "pkg:generic/vendorx/rtalloc" },
    "ranges": [{ "type": "SEMVER",
                 "events": [{ "introduced": "2.3.0" }, { "fixed": "2.5.1" }] }],
    "database_specific": {
      "version_confidence": 0.92,
      "range_source": "changelog"
    }
  }],
  "references": [
    { "type": "REPORT", "url": "https://…/issues/1234" }
  ],
  "database_specific": {
    "finding_class": "functional",
    "functional_severity": "major",
    "symptom_keywords": ["incorrect result", "race condition"],
    "upstream_status": "fixed",
    "workaround_available": true,
    "workaround_summary": "Sérialiser les appels via mutex applicatif",
    "evidence_refs": ["sha256:ab12…"],
    "extraction": {
      "extractor_id": "github-issues-extractor",
      "extractor_version": "1.4.0",
      "model_id": null,
      "prompt_version": null,
      "confidence": 0.97,
      "source_spans": [{ "evidence": "sha256:ab12…", "loc": "issue.body[120:480]" }]
    },
    "ingestion": {
      "status": "candidate",
      "tier": "A",
      "decided_by": null,
      "decided_at": null,
      "rationale": null
    }
  }
}
```

Champs d'extension — sémantique :

| Champ | Valeurs | Exigence |
|-------|---------|----------|
| `finding_class` | `functional` \| `security` \| `documentation` \| `performance` | DOIT |
| `functional_severity` | `critical` \| `major` \| `minor` \| `cosmetic` (sévérité **amont**, indépendante de l'impact local) | DOIT |
| `upstream_status` | `open` \| `fixed` \| `wontfix` \| `duplicate` \| `unknown` | DOIT |
| `workaround_available` / `workaround_summary` | bool / texte | DEVRAIT |
| `evidence_refs` | ≥ 1 hash de preuve | DOIT |
| `extraction.confidence` | [0,1] | DOIT |
| `extraction.source_spans` | localisation de chaque assertion dans la preuve | DOIT pour extraction IA ; DEVRAIT sinon |
| `ingestion.status` | `candidate` \| `ingested_auto` \| `ingested_reviewed` \| `rejected` | DOIT |

* E-4.3.2 — La sévérité fonctionnelle est celle déclarée ou inférée **côté
  amont**. La qualification d'impact sur le logiciel critique est hors
  périmètre de ce document et NE DOIT PAS être renseignée par un extracteur.
* E-4.3.3 — Tout champ inféré par IA DOIT être couvert par au moins un
  `source_span`. Une assertion sans span DOIT faire chuter la confiance
  sous le seuil d'auto-ingestion.

### 4.4 `Cursor`

État opaque de synchronisation, propriété du plugin, persisté par
l'orchestrateur.

```json
{
  "plugin_id": "github-issues",
  "scope": "pkg:generic/vendorx/rtalloc",
  "state": { "since": "2026-06-01T00:00:00Z", "etag": "W/\"abc\"", "page": 7 },
  "updated_at": "2026-06-10T09:00:00Z"
}
```

* E-4.4.1 — `collect(purl, cursor)` DOIT être idempotent : rejouer avec le
  même curseur peut produire des doublons de preuves (dédupliqués par hash)
  mais NE DOIT PAS produire d'état incohérent.

---

## 5. `PluginManifest`

Chaque plugin embarque un manifeste déclaratif (YAML), validé au chargement.

```yaml
id: github-issues
version: 1.4.0                  # SemVer
tier: A                         # A | B | C
display_name: "GitHub Issues"
collection_mode: api            # api | feed | scrape
matches:                        # prédicats de couverture
  - purl_type: [github]         # purls pkg:github/*
  - source_pattern: "https://github.com/*"
finding_seeds:                  # mots-clés de réduction d'espace (tiers B/C)
  - "crash"
  - "regression"
  - "incorrect"
  - "data corruption"
  - "workaround"
rate_limit:
  requests_per_minute: 30
  burst: 10
network:
  allowed_domains:              # allowlist STRICTE, appliquée par le sandbox
    - api.github.com
auth:
  type: token                   # none | token | oauth
  secret_ref: "vault://github/pat"   # jamais de secret en clair
extractors:                     # extracteurs compatibles, par ordre de préférence
  - github-issues-extractor@^1.0
sandbox:
  profile: standard             # standard | hardened (obligatoire pour tier C)
maintainer: "ryan@example.org"
```

Exigences :

* E-5.1 — `tier`, `collection_mode`, `network.allowed_domains` et
  `rate_limit` DOIVENT être déclarés. Un plugin sans allowlist réseau NE
  DOIT PAS être chargé.
* E-5.2 — Un plugin `tier: C` DOIT déclarer `sandbox.profile: hardened` et
  au moins un `finding_seeds`.
* E-5.3 — Les secrets DOIVENT être référencés indirectement
  (`secret_ref`) ; le manifeste NE DOIT PAS contenir de credential.
* E-5.4 — `matches` DOIT permettre à l'orchestrateur de router un purl vers
  le plugin sans exécuter de code du plugin.

---

## 6. Contrat `SourcePlugin`

```python
class SourcePlugin(Protocol):
    manifest: PluginManifest

    def matches(self, purl: str) -> bool:
        """Évaluation rapide, pure, sans I/O. Cohérente avec manifest.matches."""

    def discover(self, purl: str) -> list[SourceTarget]:
        """Optionnel (tiers B/C) : localise les URLs candidates pour un composant
        (page issues, changelog, KB vendeur). Peut faire de l'I/O réseau."""

    def collect(self, purl: str, cursor: Cursor | None) -> CollectResult:
        """Collecte incrémentale. Retourne les preuves brutes + nouveau curseur."""

@dataclass(frozen=True)
class CollectResult:
    evidences: list[RawEvidence]
    next_cursor: Cursor
    exhausted: bool            # False => l'orchestrateur replanifie une page suivante
    diagnostics: list[Diag]    # erreurs partielles, ratios de pages en échec
```

### 6.1 Cycle de vie et exécution

* E-6.1 — Un plugin DOIT être **sans état persistant propre** : tout état de
  synchronisation passe par le `Cursor`, tout artefact par l'Evidence Store.
* E-6.2 — `collect()` s'exécute dans un **sandbox** (processus isolé) avec :
  filesystem en lecture seule hors répertoire de travail, egress réseau
  restreint à `network.allowed_domains`, budgets CPU/mémoire/temps imposés
  par l'orchestrateur.
* E-6.3 — Le plugin NE DOIT PAS écrire directement dans la base de findings
  ni invoquer d'extracteur. Frontière stricte collecte / extraction.
* E-6.4 — Le respect de `rate_limit` est appliqué par l'orchestrateur
  (token bucket par plugin et par domaine) ; le plugin DEVRAIT en plus
  honorer les en-têtes `Retry-After` / `X-RateLimit-*`.
* E-6.5 — Erreurs : transitoires (réseau, 429, 5xx) → retry exponentiel par
  l'orchestrateur ; permanentes (404 sur source disparue, schéma API changé)
  → le plugin DOIT émettre un `Diag` typé ; trois échecs permanents
  consécutifs sur un scope DOIVENT lever une alerte de **fraîcheur de
  source** (la disparition d'une source est une information d'audit).
* E-6.6 — Politesse web (tiers B/C) : robots.txt respecté par défaut,
  User-Agent identifiant l'outil, cache HTTP (ETag/Last-Modified) obligatoire.

---

## 7. Contrat `Extractor`

```python
class Extractor(Protocol):
    id: str
    version: str
    deterministic: bool        # True = parseur pur ; False = IA impliquée

    def accepts(self, ev: RawEvidence) -> bool
    def extract(self, ev: RawEvidence) -> list[CandidateFinding]
```

* E-7.1 — Par défaut, `extract()` NE DOIT PAS faire d'I/O réseau. Entrée :
  la preuve archivée, rien d'autre. C'est la garantie de rejouabilité.
  Exception encadrée : le mode d'enrichissement (§7.6), désactivé par
  défaut, activable par déploiement et par extracteur.
* E-7.2 — Tout finding émis DOIT porter `extractor_id`, `extractor_version`,
  et pour les extracteurs non déterministes `model_id` + `prompt_version`.
* E-7.3 — **Extracteurs IA :** la sortie du modèle DOIT être validée contre
  le JSON Schema de `CandidateFinding` ; toute sortie non conforme est
  rejetée (pas de réparation silencieuse). Le contenu de la preuve DOIT être
  traité comme **non fiable** (injection de prompt) : le prompt système DOIT
  interdire le suivi d'instructions contenues dans la preuve, et la sortie
  n'est jamais exécutée ni utilisée pour piloter la collecte.
* E-7.4 — Un extracteur IA NE DOIT PAS inventer de plage de versions : si la
  preuve ne mentionne pas de versions, `ranges` reste vide et
  `version_confidence = 0` (le finding part en revue humaine).
* E-7.5 — Normalisation des versions : conversion vers un type de range OSV
  (`SEMVER`, `ECOSYSTEM`, `GIT`) via la bibliothèque de normalisation
  centrale ; les conventions exotiques non parsables DOIVENT être conservées
  verbatim dans `database_specific.range_source` pour revue.

### 7.6 Mode d'enrichissement réseau (optionnel, opt-in)

Cas d'usage : un extracteur traite un changelog qui référence une issue
(`fixes #1234`), une page vendeur, ou un commit ; suivre ce lien au moment de
l'extraction améliore nettement la qualité du finding (plages de versions,
statut amont). Ce mode est une **feature désactivée par défaut**, activable à
deux niveaux : configuration de déploiement (`enrichment.enabled: true`) ET
déclaration explicite dans le manifeste de l'extracteur.

```yaml
# extension du manifeste (extracteur)
enrichment:
  enabled: true
  allowed_domains: [api.github.com, github.com]
  max_fetches_per_extraction: 5
  max_depth: 1                 # pas de suivi de liens transitif
```

Exigences :

* E-7.6.1 — Toute ressource récupérée en enrichissement DOIT être archivée
  comme `RawEvidence` (champ additionnel `kind: enrichment`,
  `parent_evidence` = hash de la preuve d'origine) **avant** d'être utilisée.
  Le finding référence alors la preuve primaire ET les preuves
  d'enrichissement dans `evidence_refs`.
* E-7.6.2 — Rejouabilité préservée : le re-jeu d'une extraction DOIT
  consommer les preuves d'enrichissement archivées et NE DOIT PAS refaire
  d'appel réseau (mode replay strict). Un re-jeu avec rafraîchissement
  réseau est une nouvelle extraction, avec nouvelles preuves.
* E-7.6.3 — Les fetches d'enrichissement s'exécutent dans le même sandbox
  et sous les mêmes contraintes que la collecte : allowlist de domaines
  propre à l'extracteur, rate limiting, budgets, politesse (§6).
* E-7.6.4 — Pour un extracteur IA, les cibles d'enrichissement DOIVENT être
  des URLs extraites **littéralement** de la preuve (présentes dans le
  texte) et appartenir à l'allowlist. Le modèle NE DOIT PAS synthétiser
  d'URL. Aucune donnée issue du modèle ne paramètre la requête au-delà du
  choix parmi les URLs candidates.
* E-7.6.5 — `max_depth = 1` par défaut : une preuve d'enrichissement ne
  déclenche pas elle-même d'enrichissement. Toute valeur supérieure DOIT
  être justifiée dans le manifeste et validée à la revue du plugin.
* E-7.6.6 — Traçabilité : `extraction.enrichment_used: true` et la liste des
  fetches (URL, hash, statut) DOIVENT figurer dans le finding. La gate (§8)
  PEUT appliquer des seuils distincts aux findings enrichis.

---

## 8. Gate de validation

Décision d'ingestion, évaluée à chaque `CandidateFinding` :

```
auto_ingest ⇔  tier == A
            ∧  schéma OSV + extensions valide
            ∧  ranges non vides ET parsées (version_confidence ≥ 0.9)
            ∧  extraction.confidence ≥ 0.9
            ∧  dédup non ambiguë (cf. §9)
            ∧  extracteur deterministic == True
```

| Cas | Action |
|-----|--------|
| Toutes conditions vraies | `ingested_auto` |
| Tier A mais extraction IA, ou confiance ∈ [0.6, 0.9) | File de revue, priorité haute |
| Tier B/C, confiance ≥ 0.6 | File de revue, priorité normale |
| Confiance < 0.6 ou schéma invalide | `rejected` (conservé 90 j pour analyse des faux négatifs) |

* E-8.1 — Les seuils DOIVENT être configurables par déploiement et
  journalisés avec chaque décision.
* E-8.2 — Une décision humaine DOIT enregistrer `decided_by`, `decided_at`
  et un `rationale` libre (exigence d'audit, dans l'esprit [AMC-20-189]).
* E-8.3 — La gate NE DOIT JAMAIS auto-ingérer un finding issu d'une
  extraction non déterministe, quel que soit son score. L'IA propose,
  l'humain (ou un parseur déterministe) dispose.

---

## 9. Déduplication et aliasing

Fingerprint de rapprochement : `(purl, chevauchement de ranges,
similarité d'embedding du couple summary+details ≥ θ)`.

* E-9.1 — Deux findings rapprochés NE DOIVENT PAS être fusionnés
  destructivement : le finding canonique agrège les `evidence_refs`, et les
  identifiants secondaires sont liés via `aliases` (sémantique OSV).
* E-9.2 — Un rapprochement inter-sources (ex. issue GitHub ↔ entrée de
  changelog) avec similarité ∈ [θ_bas, θ_haut) est dit **ambigu** et DOIT
  être tranché en revue humaine (il bloque l'auto-ingestion, cf. §8).
* E-9.3 — Le rapprochement avec des CVE existantes (via `aliases` OSV)
  DEVRAIT être tenté pour éviter de dupliquer le travail des scanners sécu.

---

## 10. Traçabilité et audit

Chaîne de provenance obligatoire pour tout finding ingéré :

```
finding_id
 └─ evidence_refs[] (sha256, source_url, fetched_at, kind: primary|enrichment)
     └─ plugin_id @ plugin_version (+ manifest hash)
         └─ extractor_id @ extractor_version (+ model_id, prompt_version,
            enrichment_used, fetches[])
             └─ gate decision (status, seuils, decided_by, rationale)
```

* E-10.1 — Toute la chaîne DOIT être reconstructible hors-ligne, sans accès
  aux sources d'origine.
* E-10.2 — Les manifestes, prompts et seuils sont versionnés dans le dépôt
  de configuration ; leur hash est référencé par les décisions.
* E-10.3 — Journal d'audit en append-only (les corrections passent par de
  nouvelles entrées, jamais par mutation).

---

## 11. Sécurité

* E-11.1 — Sandbox par plugin : processus dédié, utilisateur non privilégié,
  FS minimal, egress limité à l'allowlist du manifeste, budgets de
  ressources. Profil `hardened` (tier C) : conteneur dédié, pas de DNS
  arbitraire, payloads traités comme hostiles.
* E-11.2 — Les payloads HTML/PDF NE DOIVENT être parsés que par des
  bibliothèques maintenues, dans le sandbox, jamais dans le processus cœur.
* E-11.3 — Injection de prompt (tier B/C) : cf. E-7.3. De plus, le crawler
  contraint (discover) NE DOIT suivre que des liens du même domaine
  allowlisté, à profondeur bornée déclarée dans le manifeste.
* E-11.4 — Secrets injectés à l'exécution par le gestionnaire de secrets ;
  jamais loggés ; scopés au plugin.

---

## 12. Versionnement et compatibilité

* E-12.1 — Schémas (`RawEvidence`, `CandidateFinding`, `PluginManifest`,
  API plugin) versionnés en SemVer. Règle héritée d'OSV : un consommateur
  d'une version mineure N DOIT pouvoir lire N+1 en ignorant les champs
  inconnus.
* E-12.2 — L'orchestrateur DOIT refuser un plugin dont la version majeure
  d'API ne correspond pas à la sienne.
* E-12.3 — Une montée de version d'extracteur DEVRAIT déclencher un re-jeu
  ciblé sur les preuves archivées des findings en statut `candidate` ou
  `rejected` (récupération de faux négatifs).

---

## 13. Checklist de conformité d'un plugin

Un plugin est conforme s'il satisfait :

1. Manifeste valide (E-5.1 à E-5.4), allowlist réseau déclarée.
2. `matches()` pur et cohérent avec le manifeste.
3. `collect()` idempotent, incrémental (curseur), sans état caché.
4. Preuves brutes archivées avant tout parsing (E-4.2.1).
5. Aucun accès direct à la base de findings (E-6.3).
6. Diagnostics typés pour les échecs permanents (E-6.5).
7. Tests : rejeu d'un corpus de preuves de référence → extraction
   identique bit-à-bit (extracteurs déterministes) ou conforme au schéma
   avec spans (extracteurs IA).
8. Si enrichissement déclaré : allowlist dédiée, archivage systématique des
   fetches (E-7.6.1), re-jeu strict sans réseau vérifié (E-7.6.2).

---

*Prochaines specs : `SPEC-qualification-vex.md` (workflow d'impact, mapping
CSAF), `SPEC-ingestion-sbom.md` (watchlist, purl matching).*
