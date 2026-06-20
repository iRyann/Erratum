# cots-findings — prototype

Implémentation de référence de `SPEC-collecte-plugins.md` v0.2.

```
erratum/
  models.py        RawEvidence, CandidateFinding (OSV étendu), Cursor   (§4)
  evidence_store.py  store immuable adressé par sha256                  (§4.2, E-10.3)
  plugin_api.py    PluginManifest + contrats SourcePlugin/Extractor     (§5–7)
  plugins/github_issues.py        plugin Tier A (collecte seule)        (§6)
  extractors/github_issues_extractor.py  extracteur déterministe        (§7)
  gate.py          gate de validation                                   (§8)
  demo.py          pipeline bout-en-bout (réseau réel)
```

## Lancer

    python -m erratum.demo pkg:github/<owner>/<repo> out

## Statut

Prototype de validation d'architecture. Non couvert : enrichissement (§7.6),
sandboxing réel, déduplication (§9), persistance des findings ingérés,
plugins Tier B/C.

![Alt](https://repobeats.axiom.co/api/embed/76e7c23dc10cecefaedb61fc5d7af7a400c8b9d3.svg "Repobeats analytics image")
