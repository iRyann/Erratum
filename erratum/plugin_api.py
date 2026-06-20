"""Contrats de plugin et d'extracteur — §5, §6, §7 de la spec."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator, Protocol, runtime_checkable

from .models import CandidateFinding, Cursor, RawEvidence


@dataclass(frozen=True)
class PluginManifest:
    """§5 — déclaratif, validable sans exécuter le plugin (E-5.4)."""
    id: str
    version: str
    tier: str                                  # A | B | C
    display_name: str
    collection_mode: str                       # api | feed | scrape
    purl_types: tuple[str, ...]                # routage par type de purl
    allowed_domains: tuple[str, ...]           # E-5.1 : allowlist obligatoire
    requests_per_minute: int = 30
    finding_seeds: tuple[str, ...] = ()
    sandbox_profile: str = "standard"

    def validate(self) -> None:
        if not self.allowed_domains:
            raise ValueError(f"{self.id}: allowlist réseau vide (E-5.1)")
        if self.tier == "C" and self.sandbox_profile != "hardened":
            raise ValueError(f"{self.id}: tier C exige sandbox hardened (E-5.2)")
        if self.tier == "C" and not self.finding_seeds:
            raise ValueError(f"{self.id}: tier C exige des finding_seeds (E-5.2)")


@dataclass
class Diag:
    level: str          # warning | error
    code: str           # ex. SOURCE_GONE, SCHEMA_DRIFT, RATE_LIMITED
    message: str
    scope: str | None = None


@dataclass
class CollectResult:
    evidences: list[RawEvidence]
    next_cursor: Cursor
    exhausted: bool
    diagnostics: list[Diag] = field(default_factory=list)


@runtime_checkable
class SourcePlugin(Protocol):
    manifest: PluginManifest

    def matches(self, purl: str) -> bool: ...
    def collect(self, purl: str, cursor: Cursor | None) -> CollectResult: ...


@runtime_checkable
class Extractor(Protocol):
    id: str
    version: str
    deterministic: bool

    def accepts(self, ev: RawEvidence) -> bool: ...
    def extract(self, ev: RawEvidence) -> list[CandidateFinding]: ...
