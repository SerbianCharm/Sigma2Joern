"""Output formats: human readable text, JSON and SARIF 2.1.0."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Iterable

from . import __version__
from .events import ProcEvent
from .matcher import Finding

GAP_MARK = "«…»"  # «…»


def _loc(f: Finding) -> str:
    o = f.event.origin
    return f"{o.file}:{o.line}" if o.line else o.file


def finding_to_dict(f: Finding) -> dict:
    o = f.event.origin
    return {
        "confidence": f.level,
        "rule": {"id": f.rule.rule_id, "title": f.rule.title, "severity": f.rule.severity,
                 "tags": f.rule.tags, "path": f.rule.path},
        "platform": f.platform,
        "location": {"file": o.file, "line": o.line, "method": o.method, "code": o.code,
                     "sink": o.sink, "language": o.language},
        "event": {k: v.render(GAP_MARK) for k, v in f.fields.items()},
        "event_kind": f.event.kind,
        "derived_via": f.event.via,
        "unknown_fields": sorted(f.evaluation.unknown_fields),
    }


def to_json(findings: list[Finding]) -> str:
    return json.dumps({"tool": "sigma2joern", "version": __version__,
                       "findings": [finding_to_dict(f) for f in findings]}, indent=2, ensure_ascii=False)


def to_text(findings: list[Finding], color: bool = False) -> str:
    if not findings:
        return "No Sigma rule matched the extracted process starts."
    by_loc: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_loc[_loc(f)].append(f)
    lines: list[str] = []
    tags = {"match": "MATCH   ", "conditional": "COND.   ", "possible": "POSSIBLE"}
    for loc, items in by_loc.items():
        first = items[0].event.origin
        lines.append(f"{loc}  [{first.sink}]")
        lines.append(f"    code: {first.code.strip().splitlines()[0] if first.code.strip() else ''}")
        for f in items:
            ev = f.fields
            lines.append(f"  {tags[f.level]} {f.rule.severity:<8} {f.rule.title}  ({f.rule.rule_id[:8]}, {f.platform})")
            lines.append(f"           Image: {ev['Image'].render(GAP_MARK)}")
            lines.append(f"           CommandLine: {ev['CommandLine'].render(GAP_MARK)}")
            if f.level != "match" and f.evaluation.unknown_fields:
                lines.append(f"           depends on: {', '.join(sorted(f.evaluation.unknown_fields))}")
        lines.append("")
    counts = defaultdict(int)
    for f in findings:
        counts[f.level] += 1
    lines.append("Summary: " + ", ".join(f"{counts[k]} {k}" for k in ("match", "conditional", "possible") if counts[k]))
    lines.append(f"({GAP_MARK} = value not determinable statically)")
    return "\n".join(lines)


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "informational": "note"}


def to_sarif(findings: list[Finding]) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rid = f.rule.rule_id or f.rule.title
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f.rule.title,
                "shortDescription": {"text": f.rule.title},
                "fullDescription": {"text": (f.rule.rule.description or f.rule.title).strip()},
                "properties": {"tags": f.rule.tags, "sigma-level": f.rule.severity},
            }
        o = f.event.origin
        region = {"startLine": o.line} if o.line else {}
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f.rule.severity, "warning") if f.level == "match" else "note",
            "message": {"text": f"{f.rule.title} ({f.level}): process start "
                                f"{f.fields['CommandLine'].render(GAP_MARK)}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": o.file}, "region": region}}],
            "properties": {"confidence": f.level, "platform": f.platform,
                           "unknownFields": sorted(f.evaluation.unknown_fields)},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "sigma2joern", "version": __version__,
                                "informationUri": "https://github.com/SerbianCharm/Sigma2Joern",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def events_to_text(events: Iterable[ProcEvent], platforms: Iterable[str]) -> str:
    lines: list[str] = []
    for ev in events:
        o = ev.origin
        lines.append(f"{o.file}:{o.line}  [{o.sink}] kind={ev.kind}" + (f" via={ev.via}" if ev.via else ""))
        for p in platforms:
            if p not in ev.platforms:
                continue
            f = ev.fields(p)
            lines.append(f"    {p:<7} Image={f['Image'].render(GAP_MARK)}  CommandLine={f['CommandLine'].render(GAP_MARK)}")
    return "\n".join(lines) if lines else "No process-creating calls found."
