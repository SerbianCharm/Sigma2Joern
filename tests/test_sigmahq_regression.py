"""Validation against SigmaHQ's regression data (real Sysmon events that must match their rule).

Run with a checkout of https://github.com/SigmaHQ/sigma:

    SIGMAHQ_DIR=/path/to/sigma python -m pytest tests/test_sigmahq_regression.py -q

1. Semantics: with all fields known, every regression event must match its rule.
2. Soundness: with only Image/CommandLine/OriginalFileName known (what static analysis can
   see), the result must never be "no match".
3. Soundness of partial values: if parts of the command line are replaced by gaps and the
   evaluator still claims a definite match, every random filling of the gaps must match.
"""

import json
import os
import random
from pathlib import Path

import pytest
import yaml

from sigma2joern.evaluator import evaluate, load_rules
from sigma2joern.pstring import GAP, PStr, Tri

SIGMA = os.environ.get("SIGMAHQ_DIR")
pytestmark = pytest.mark.skipif(not SIGMA, reason="set SIGMAHQ_DIR to a SigmaHQ checkout")


def _events(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8").strip()
    decoder, pos, docs = json.JSONDecoder(), 0, []
    while pos < len(text):  # one or several concatenated JSON documents
        doc, end = decoder.raw_decode(text, pos)
        docs.append(doc)
        pos = end
        while pos < len(text) and text[pos].isspace():
            pos += 1
    out = []
    for d in docs:
        data = d.get("Event", {}).get("EventData") or {}
        out.append({k: str(v) for k, v in data.items() if v is not None})
    return out


@pytest.fixture(scope="module")
def cases():
    rules, _ = load_rules([str(p) for p in Path(SIGMA).glob("rules*")])
    by_id = {r.rule_id: r for r in rules}
    result = []
    for info in Path(SIGMA, "regression_data").rglob("info.yml"):
        meta = yaml.safe_load(info.read_text(encoding="utf-8"))
        rid = meta["rule_metadata"][0]["id"]
        if rid not in by_id:
            continue  # not a process_creation rule
        for test in meta.get("regression_tests_info", []):
            json_path = Path(SIGMA, test["path"]).with_suffix(".json")
            if json_path.exists():
                result.append((by_id[rid], _events(json_path), test.get("match_count", 1)))
    assert len(result) > 100
    return result


def _known(data: dict) -> dict:
    return {k: PStr.known(v) for k, v in data.items()}


def test_semantics_full_knowledge(cases):
    failures = []
    for rule, events, expected in cases:
        hits = sum(evaluate(rule, _known(e)).strict is Tri.TRUE for e in events)
        if hits < min(expected, len(events)):
            failures.append(rule.title)
    print(f"\n{len(cases) - len(failures)}/{len(cases)} regression cases match with full knowledge")
    assert not failures, failures


def test_soundness_static_view(cases):
    false_negatives = []
    levels = {"match": 0, "conditional": 0, "possible": 0}
    for rule, events, _ in cases:
        for e in events:
            if evaluate(rule, _known(e)).strict is not Tri.TRUE:
                continue
            static = {k: PStr.known(e[k]) for k in ("Image", "CommandLine", "OriginalFileName") if k in e}
            res = evaluate(rule, static)
            if res.strict is Tri.FALSE:
                false_negatives.append(rule.title)
            else:
                levels[res.level] += 1
    print(f"\nstatic view of true positives: {levels}")
    assert not false_negatives, false_negatives


def test_soundness_with_gaps(cases):
    rnd = random.Random(1)
    checked = 0
    for rule, events, _ in cases:
        for e in events:
            full = _known(e)
            if evaluate(rule, full).strict is not Tri.TRUE or "CommandLine" not in e:
                continue
            cl = e["CommandLine"]
            for _ in range(5):
                a = rnd.randint(0, len(cl))
                b = rnd.randint(a, len(cl))
                gapped = dict(full, CommandLine=PStr((cl[:a], GAP, cl[b:])))
                res = evaluate(rule, gapped).strict
                assert res is not Tri.FALSE, (rule.title, cl, a, b)
                if res is Tri.TRUE:  # must hold for arbitrary fillings
                    for _ in range(5):
                        fill = "".join(rnd.choice("ab /-\\\"'.:") for _ in range(rnd.randint(0, 12)))
                        filled = dict(full, CommandLine=PStr.known(cl[:a] + fill + cl[b:]))
                        assert evaluate(rule, filled).strict is Tri.TRUE, (rule.title, cl, a, b, fill)
                        checked += 1
    print(f"\n{checked} random gap fillings confirmed definite matches")
