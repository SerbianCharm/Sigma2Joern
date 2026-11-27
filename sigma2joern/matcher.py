"""Match synthetic process events against loaded Sigma rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .evaluator import LEVELS, Evaluation, LoadedRule, evaluate_lowered
from .events import PLATFORMS, ProcEvent
from .pstring import PStr

LEVEL_RANK = {name: len(LEVELS) - i for i, name in enumerate(LEVELS)}  # match=3, conditional=2, possible=1


@dataclass
class Finding:
    rule: LoadedRule
    event: ProcEvent
    platform: str
    evaluation: Evaluation
    fields: dict[str, PStr]

    @property
    def level(self) -> str:
        return self.evaluation.level or "none"


def match_events(
    events: Iterable[ProcEvent],
    rules: list[LoadedRule],
    min_level: str = "conditional",
    platforms: Iterable[str] = PLATFORMS,
    context: dict[str, str] | None = None,
    assume_path: bool = True,
) -> list[Finding]:
    """Evaluate every rule against every event. Per rule and call site only the best
    finding is kept (the started program is preferred over the shell that starts it)."""
    allowed = set(platforms)
    threshold = LEVEL_RANK[min_level]
    ctx = {k: PStr.known(v) for k, v in (context or {}).items()}
    findings: dict[tuple, Finding] = {}
    for ev in events:
        fields_by_platform = {p: {**ev.fields(p, assume_path), **ctx}
                              for p in ev.platforms if p in allowed}
        lowered = {p: {k.lower(): v for k, v in f.items()} for p, f in fields_by_platform.items()}
        for rule in rules:
            best: Finding | None = None
            for platform in rule.platforms:
                if platform not in fields_by_platform:
                    continue
                result = evaluate_lowered(rule, lowered[platform])
                lvl = result.level
                if lvl is None or LEVEL_RANK[lvl] < threshold:
                    continue
                if best is None or LEVEL_RANK[lvl] > LEVEL_RANK[best.level]:
                    best = Finding(rule, ev, platform, result, fields_by_platform[platform])
            if best is None:
                continue
            key = (rule.rule_id or rule.path, ev.origin)
            old = findings.get(key)
            if old is None or _better(best, old):
                findings[key] = best
    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
    return sorted(
        findings.values(),
        key=lambda f: (-LEVEL_RANK[f.level], -severity_rank.get(f.rule.severity, 0),
                       f.event.origin.file, f.event.origin.line or 0, f.rule.title),
    )


def _better(new: Finding, old: Finding) -> bool:
    if LEVEL_RANK[new.level] != LEVEL_RANK[old.level]:
        return LEVEL_RANK[new.level] > LEVEL_RANK[old.level]
    return old.event.kind == "shell" and new.event.kind != "shell"
