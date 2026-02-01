"""Base evidence collector with common evidence envelope structure."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class Evidence:
    """A single piece of SOC 2 evidence."""

    source: str
    evidence_type: str
    collected_at: str
    data: dict[str, Any]
    controls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BaseEvidenceCollector:
    """Base class for evidence collectors."""

    source: str = ""

    def _make_evidence(
        self,
        evidence_type: str,
        data: dict[str, Any],
        controls: list[str] | None = None,
    ) -> Evidence:
        return Evidence(
            source=self.source,
            evidence_type=evidence_type,
            collected_at=datetime.now(timezone.utc).isoformat(),
            data=data,
            controls=controls or [],
        )
