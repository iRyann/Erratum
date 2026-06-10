# cots-findings — prototype

Implémentation de référence de `SPEC-collecte-plugins.md` v0.2.

```
cots_findings/
  models.py        RawEvidence, CandidateFinding (OSV étendu), Cursor   (§4)
  evidence_store.py  store immuable adressé par sha256                  (§4.2, E-10.3)
  plugin_api.py    PluginManifest + contrats SourcePlugin/Extractor     (§5–7)
  plugins/github_issues.py        plugin Tier A (collecte seule)        (§6)
  extractors/github_issues_extractor.py  extracteur déterministe        (§7)
  gate.py          gate de validation                                   (§8)
  demo.py          pipeline bout-en-bout (réseau réel)
test_replay.py     test de rejeu sur corpus de référence                (§13.7)
```

## Lancer

    python -m cots_findings.demo pkg:github/<owner>/<repo> out
    python test_replay.py        # sans réseau

## Statut

Prototype de validation d'architecture. Non couvert : enrichissement (§7.6),
sandboxing réel, déduplication (§9), persistance des findings ingérés,
plugins Tier B/C.
