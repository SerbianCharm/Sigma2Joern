"""Three-valued evaluation of Sigma rules (parsed by pySigma) against synthetic events.

Fields the static analysis cannot know (ParentImage, User, Hashes, ...) are UNKNOWN.
Each rule/event pair gets one of three confidence levels:

* ``match``    - the rule matches no matter what the unknown values are
* ``conditional`` - the detection part matches; only exclusion filters on unknown
                 context (e.g. ``not ParentImage ...``) could still suppress the alert
* ``possible`` - the result depends on unknown values in the detection part itself
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from .pstring import GAP, QMARK, STAR, GlobPattern, PStr, Tri

try:  # available in recent pySigma versions
    from sigma.types import SigmaCasedString
except ImportError:  # pragma: no cover
    SigmaCasedString = ()  # type: ignore[assignment,misc]

SUPPORTED_CATEGORIES = ("process_creation",)
LEVELS = ("match", "conditional", "possible")


@dataclass
class LoadedRule:
    rule: SigmaRule
    path: str
    trees: list[Any]
    platforms: tuple[str, ...]
    compiled: list | None = None

    @property
    def title(self) -> str:
        return self.rule.title

    @property
    def rule_id(self) -> str:
        return str(self.rule.id) if self.rule.id else ""

    @property
    def severity(self) -> str:
        return self.rule.level.name.lower() if self.rule.level else "unknown"

    @property
    def tags(self) -> list[str]:
        return [f"{t.namespace}.{t.name}" for t in (self.rule.tags or [])]


@dataclass
class RuleLoadStats:
    files: int = 0
    rules: int = 0
    loaded: int = 0
    skipped_category: int = 0
    skipped_files: int = 0
    errors: list[tuple[str, str]] = field(default_factory=list)


def _rule_files(paths: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            files.extend(sorted(x for x in path.rglob("*") if x.suffix in (".yml", ".yaml")))
        elif path.exists():
            files.append(path)
        else:
            raise FileNotFoundError(p)
    return files


def load_rules(paths: Iterable[str], categories: tuple[str, ...] = SUPPORTED_CATEGORIES) -> tuple[list[LoadedRule], RuleLoadStats]:
    stats = RuleLoadStats()
    loaded: list[LoadedRule] = []
    for f in _rule_files(paths):
        stats.files += 1
        text = f.read_text(encoding="utf-8")
        if not any(cat in text for cat in categories):  # cheap pre-filter, avoids parsing other rules
            stats.skipped_files += 1
            continue
        try:
            collection = SigmaCollection.from_yaml(text, collect_errors=True)
        except Exception as exc:  # broken YAML etc.
            stats.errors.append((str(f), str(exc)))
            continue
        for rule in collection.rules:
            if not isinstance(rule, SigmaRule):
                continue  # correlation rules, filters
            stats.rules += 1
            if rule.errors:
                stats.errors.append((str(f), str(rule.errors[0])))
                continue
            if (rule.logsource.category or "") not in categories:
                stats.skipped_category += 1
                continue
            try:
                trees = [c.parsed for c in rule.detection.parsed_condition]
            except Exception as exc:
                stats.errors.append((str(f), str(exc)))
                continue
            product = (rule.logsource.product or "").lower()
            platforms = (product,) if product in ("windows", "linux", "macos") else ("windows", "linux")
            loaded.append(LoadedRule(rule, os.fspath(f), trees, platforms))
            stats.loaded += 1
    return loaded, stats


# ---------------------------------------------------------------------------
# value matching
# ---------------------------------------------------------------------------

_MISSING = object()


def _glob(value: SigmaString, keyword: bool = False) -> GlobPattern | None:
    """Compiled wildcard pattern for a SigmaString (cached on the object itself).
    Keywords (values without field) are searched anywhere, i.e. they get implicit wildcards."""
    attr = "_s2j_kw" if keyword else "_s2j_glob"
    cached = getattr(value, attr, _MISSING)
    if cached is not _MISSING:
        return cached  # type: ignore[return-value]
    items: list[str] = []
    ok = True
    for item in value.s:
        if isinstance(item, str):
            items.append(item)
        elif item == SpecialChars.WILDCARD_MULTI:
            items.append(STAR)
        elif item == SpecialChars.WILDCARD_SINGLE:
            items.append(QMARK)
        else:  # placeholder (%...%): unknown list of values
            ok = False
    if keyword:
        items = [STAR] + items + [STAR]
    cased = bool(SigmaCasedString) and isinstance(value, SigmaCasedString)
    pattern = GlobPattern(items, case_sensitive=cased) if ok else None
    try:
        setattr(value, attr, pattern)
    except AttributeError:  # pragma: no cover - objects without __dict__
        pass
    return pattern


def _regex(value: SigmaRegularExpression) -> re.Pattern | None:
    cached = getattr(value, "_s2j_re", _MISSING)
    if cached is not _MISSING:
        return cached  # type: ignore[return-value]
    flags = 0
    for flag in value.flags:
        flags |= value.sigma_to_python_flags[flag]
    try:
        compiled: re.Pattern | None = re.compile(str(value.regexp), flags)
    except re.error:
        compiled = None
    try:
        value._s2j_re = compiled  # type: ignore[attr-defined]
    except AttributeError:  # pragma: no cover
        pass
    return compiled


def match_value(value: Any, actual: PStr | None, keyword: bool = False) -> Tri:
    """Match one Sigma value against a (partially) known field value; None = field unknown."""
    if isinstance(value, SigmaExpansion):
        result = Tri.FALSE
        for v in value.values:
            result = result | match_value(v, actual, keyword)
            if result is Tri.TRUE:
                break
        return result
    if actual is None:
        return Tri.UNKNOWN
    if isinstance(value, SigmaString):
        pattern = _glob(value, keyword)
        return pattern.match(actual) if pattern else Tri.UNKNOWN
    if isinstance(value, SigmaRegularExpression):
        rx = _regex(value)
        if rx is None:
            return Tri.UNKNOWN
        if not actual.has_gap:
            return Tri.TRUE if rx.search(actual.text) else Tri.FALSE
        return _regex_partial(rx, actual)
    if isinstance(value, SigmaNull):
        if actual.has_gap:
            return Tri.UNKNOWN
        return Tri.TRUE if actual.text == "" else Tri.FALSE
    if isinstance(value, SigmaExists):
        return Tri.TRUE if value.exists else Tri.FALSE
    if isinstance(value, (SigmaNumber, SigmaBool)):
        if actual.has_gap:
            return Tri.UNKNOWN
        expected = str(value.number if isinstance(value, SigmaNumber) else value.boolean)
        return Tri.TRUE if actual.text.strip().lower() == expected.lower() else Tri.FALSE
    if isinstance(value, SigmaCIDRExpression):
        if actual.has_gap:
            return Tri.UNKNOWN
        try:
            return Tri.TRUE if ipaddress.ip_address(actual.text.strip()) in value.network else Tri.FALSE
        except ValueError:
            return Tri.FALSE
    if isinstance(value, (SigmaFieldReference, SigmaCompareExpression)):
        return Tri.UNKNOWN  # needs other fields / numeric context
    return Tri.UNKNOWN


def _regex_features(pattern: str) -> tuple[bool, bool, bool, bool]:
    """(start anchor, end anchor, word boundary, lookaround) used outside character classes."""
    start = end = boundary = look = False
    i, in_class = 0, False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            nxt = pattern[i + 1:i + 2]
            if not in_class:
                start |= nxt == "A"
                end |= nxt in ("Z", "z")
                boundary |= nxt in ("b", "B")
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
            if pattern[i + 1:i + 2] == "^":
                i += 1
            if pattern[i + 1:i + 2] == "]":  # literal ] as first class member
                i += 1
        elif c == "^":
            start = True
        elif c == "$":
            end = True
        elif c == "(" and pattern[i + 1:i + 4] in ("?<=", "?<!") or pattern[i:i + 3] in ("(?=", "(?!"):
            look = True
        i += 1
    return start, end, boundary, look


def _regex_partial(rx: re.Pattern, actual: PStr) -> Tri:
    """Sound check of an unanchored regex search on a partially known value: TRUE if a match
    lies completely inside a known part (independent of the unknown parts), else UNKNOWN."""
    start, end, boundary, look = _regex_features(rx.pattern)
    if look:
        return Tri.UNKNOWN
    parts = actual.parts
    for idx, part in enumerate(parts):
        if part is GAP:
            continue
        gap_before, gap_after = idx > 0, idx < len(parts) - 1
        if (start and gap_before) or (end and gap_after):
            continue
        for m in rx.finditer(part):
            a, b = m.span()
            if boundary and ((gap_before and a == 0) or (gap_after and b == len(part))):
                continue
            return Tri.TRUE
    return Tri.UNKNOWN


# ---------------------------------------------------------------------------
# condition trees: compiled once per rule into tuples of
#   (0, children) AND  |  (1, children) OR  |  (2, child) NOT  |  (3, label, fn) LEAF
# with integers 0/1/2 for FALSE/UNKNOWN/TRUE (Kleene logic: AND=min, OR=max, NOT=2-x)
# ---------------------------------------------------------------------------

@dataclass
class Evaluation:
    strict: Tri
    optimistic: Tri
    unknown_fields: set[str]

    @property
    def level(self) -> str | None:
        if self.strict is Tri.TRUE:
            return "match"
        if self.optimistic is Tri.TRUE:
            return "conditional"
        if self.strict is Tri.UNKNOWN:
            return "possible"
        return None


def _compile_matcher(value: Any, keyword: bool) -> Callable[[PStr | None], int]:
    if isinstance(value, SigmaExpansion):
        subs = [_compile_matcher(v, keyword) for v in value.values]

        def expansion(actual: PStr | None) -> int:
            best = 0
            for sub in subs:
                r = sub(actual)
                if r > best:
                    best = r
                    if best == 2:
                        break
            return best
        return expansion
    if isinstance(value, SigmaString):
        pattern = _glob(value, keyword)
        if pattern is None:
            return lambda actual: 1

        def glob(actual: PStr | None, pattern: GlobPattern = pattern) -> int:
            return 1 if actual is None else pattern.match_int(actual)
        return glob
    return lambda actual: int(match_value(value, actual, keyword))


def _field_reference(field_name: str, ref: SigmaFieldReference) -> Callable[[dict[str, PStr]], int]:
    """``field|fieldref: other`` compares two fields of the same event (as pySigma does)."""
    f1, f2 = field_name.lower(), ref.field.lower()

    def compare(fields: dict[str, PStr]) -> int:
        a, b = fields.get(f1), fields.get(f2)
        if a is None or b is None or a.has_gap or b.has_gap:
            return 1
        x, y = a.text, b.text
        if ref.starts_with and ref.ends_with:
            ok = y in x
        elif ref.starts_with:
            ok = x.startswith(y)
        elif ref.ends_with:
            ok = x.endswith(y)
        else:
            ok = x == y
        return 2 if ok else 0
    return compare


def _compile_leaf(field_name: str | None, value: Any) -> tuple:
    if field_name is None:  # keyword search over all fields
        sub = _compile_matcher(value, keyword=True)

        def keyword(fields: dict[str, PStr]) -> int:
            for v in fields.values():
                if sub(v) == 2:
                    return 2
            return 1  # unknown fields might contain the keyword
        return (3, "<keyword>", keyword)
    if isinstance(value, SigmaFieldReference):
        return (3, field_name, _field_reference(field_name, value))
    matcher = _compile_matcher(value, keyword=False)
    key = field_name.lower()

    def leaf(fields: dict[str, PStr]) -> int:
        return matcher(fields.get(key))
    return (3, field_name, leaf)


def compile_tree(n: Any) -> tuple:
    if isinstance(n, ConditionAND):
        return (0, tuple(compile_tree(a) for a in n.args))
    if isinstance(n, ConditionOR):
        return (1, tuple(compile_tree(a) for a in n.args))
    if isinstance(n, ConditionNOT):
        return (2, compile_tree(n.args[0]))
    if isinstance(n, ConditionFieldEqualsValueExpression):
        return _compile_leaf(n.field, n.value)
    if isinstance(n, ConditionValueExpression):
        return _compile_leaf(None, n.value)
    return (3, "<unsupported>", lambda fields: 1)


def _run(node: tuple, fields: dict[str, PStr], negated: bool, assume: bool, unknown: set[str]) -> int:
    kind = node[0]
    if kind == 3:
        r = node[2](fields)
        if r == 1:
            unknown.add(node[1])
            if assume and negated:
                return 0  # optimistic: exclusion filters on unknown context do not apply
        return r
    if kind == 0:
        best = 2
        for child in node[1]:
            r = _run(child, fields, negated, assume, unknown)
            if r < best:
                best = r
                if best == 0:
                    return 0
        return best
    if kind == 1:
        best = 0
        for child in node[1]:
            r = _run(child, fields, negated, assume, unknown)
            if r > best:
                best = r
                if best == 2:
                    return 2
        return best
    return 2 - _run(node[1], fields, not negated, assume, unknown)


def evaluate_lowered(rule: LoadedRule, fields: dict[str, PStr]) -> Evaluation:
    """Evaluate a rule; ``fields`` must use lower-case field names."""
    if rule.compiled is None:
        rule.compiled = [compile_tree(t) for t in rule.trees]
    unknown: set[str] = set()
    strict = 0
    for tree in rule.compiled:
        strict = max(strict, _run(tree, fields, False, False, unknown))
        if strict == 2:
            return Evaluation(Tri.TRUE, Tri.TRUE, unknown)
    if strict == 0:
        return Evaluation(Tri.FALSE, Tri.FALSE, set())
    optimistic = 0
    for tree in rule.compiled:
        optimistic = max(optimistic, _run(tree, fields, False, True, set()))
    return Evaluation(Tri(strict), Tri(optimistic), unknown)


def evaluate(rule: LoadedRule, fields: dict[str, PStr]) -> Evaluation:
    return evaluate_lowered(rule, {k.lower(): v for k, v in fields.items()})
