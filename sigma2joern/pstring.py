"""Partially known strings and three-valued glob matching.

Static analysis rarely knows a command line completely: ``"cmd /c " + user_input``
has a known prefix and an unknown rest. A :class:`PStr` models such a value as a
sequence of known text parts and unknown gaps (:data:`GAP`).

Matching a Sigma wildcard pattern against a ``PStr`` therefore has three outcomes
(:class:`Tri`):

* ``TRUE``    - every possible concrete value matches (the known parts suffice)
* ``FALSE``   - no possible concrete value matches
* ``UNKNOWN`` - it depends on what the gaps contain at runtime

The implementation is *sound*: it never answers ``TRUE`` or ``FALSE`` when the
other answer is possible. In rare corner cases it answers ``UNKNOWN`` although a
definite answer would be possible (e.g. ``?`` wildcards next to gaps).
"""

from __future__ import annotations

import re
from enum import IntEnum
from functools import lru_cache
from typing import Iterable, Sequence

GAP = None  # marker for an unknown part inside a PStr


class Tri(IntEnum):
    """Kleene three-valued logic with FALSE < UNKNOWN < TRUE."""

    FALSE = 0
    UNKNOWN = 1
    TRUE = 2

    def __and__(self, other: "Tri") -> "Tri":  # type: ignore[override]
        return Tri(min(self, other))

    def __or__(self, other: "Tri") -> "Tri":  # type: ignore[override]
        return Tri(max(self, other))

    def __invert__(self) -> "Tri":  # type: ignore[override]
        return Tri(2 - int(self))


class PStr:
    """An immutable, partially known string: a tuple of ``str`` parts and ``GAP`` markers."""

    __slots__ = ("parts", "_text")

    def __init__(self, parts: Iterable[str | None] = ()) -> None:
        norm: list[str | None] = []
        for p in parts:
            if p is GAP:
                if not norm or norm[-1] is not GAP:
                    norm.append(GAP)
            elif p:
                if norm and norm[-1] is not GAP:
                    norm[-1] = norm[-1] + p  # type: ignore[operator]
                else:
                    norm.append(p)
        self.parts: tuple[str | None, ...] = tuple(norm)
        self._text: str | None = None if GAP in norm else "".join(norm)  # type: ignore[arg-type]

    # -- construction -------------------------------------------------------
    @classmethod
    def known(cls, text: str) -> "PStr":
        return cls((text,))

    @classmethod
    def unknown(cls) -> "PStr":
        return cls((GAP,))

    def __add__(self, other: "PStr | str") -> "PStr":
        if isinstance(other, str):
            other = PStr.known(other)
        return PStr(self.parts + other.parts)

    def __radd__(self, other: str) -> "PStr":
        return PStr.known(other) + self

    @staticmethod
    def join(sep: str, items: Sequence["PStr"]) -> "PStr":
        parts: list[str | None] = []
        for idx, item in enumerate(items):
            if idx:
                parts.append(sep)
            parts.extend(item.parts)
        return PStr(parts)

    # -- inspection ---------------------------------------------------------
    @property
    def has_gap(self) -> bool:
        return self._text is None

    @property
    def is_unknown(self) -> bool:
        """True if nothing at all is known about the value."""
        return all(p is GAP for p in self.parts) and bool(self.parts)

    @property
    def is_empty(self) -> bool:
        return not self.parts

    @property
    def text(self) -> str:
        if self._text is None:
            raise ValueError("PStr contains unknown parts")
        return self._text

    def known_parts(self) -> list[str]:
        return [p for p in self.parts if p is not GAP]

    def items(self) -> list[str | None]:
        """Character-level view: single characters and GAP markers."""
        out: list[str | None] = []
        for p in self.parts:
            if p is GAP:
                out.append(GAP)
            else:
                out.extend(p)
        return out

    @staticmethod
    def from_items(items: Iterable[str | None]) -> "PStr":
        return PStr(items)

    def strip(self) -> "PStr":
        items = self.items()
        while items and items[0] is not GAP and items[0].isspace():
            items.pop(0)
        while items and items[-1] is not GAP and items[-1].isspace():
            items.pop()
        return PStr(items)

    def render(self, gap: str = "«…»") -> str:
        """Human readable form, unknown parts shown as «…»."""
        return "".join(gap if p is GAP else p for p in self.parts)  # type: ignore[misc]

    def to_json(self) -> list[str | None]:
        return list(self.parts)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PStr) and self.parts == other.parts

    def __hash__(self) -> int:
        return hash(self.parts)

    def __repr__(self) -> str:
        return f"PStr({self.render()!r})"


# ---------------------------------------------------------------------------
# Glob patterns (Sigma wildcards)
# ---------------------------------------------------------------------------

STAR = "\x00*"   # pattern token: any sequence (Sigma '*')
QMARK = "\x00?"  # pattern token: any single character (Sigma '?')


class GlobPattern:
    """A compiled Sigma wildcard pattern. Items are literal strings, STAR or QMARK."""

    __slots__ = ("items", "case_sensitive", "regex", "shape", "literal", "tokens")

    def __init__(self, items: Sequence[str], case_sensitive: bool = False) -> None:
        norm: list[str] = []
        for it in items:
            if it == STAR:
                if not norm or norm[-1] != STAR:
                    norm.append(STAR)
            elif it == QMARK:
                norm.append(QMARK)
            elif it:
                if norm and norm[-1] not in (STAR, QMARK):
                    norm[-1] += it
                else:
                    norm.append(it)
        self.items = tuple(norm)
        self.case_sensitive = case_sensitive
        regex = "".join(".*" if it == STAR else "." if it == QMARK else re.escape(it) for it in norm)
        self.regex = re.compile(regex, re.S if case_sensitive else re.S | re.I)

        # classify common shapes for fast evaluation on partial strings
        core = list(norm)
        lead = bool(core) and core[0] == STAR
        trail = bool(core) and core[-1] == STAR and (len(core) > 1 or not lead)
        if lead:
            core = core[1:]
        if trail and core:
            core = core[:-1]
        if len(core) == 0:
            self.shape, self.literal = ("any" if lead else "empty"), ""
        elif len(core) == 1 and core[0] not in (STAR, QMARK):
            self.shape = {(True, True): "contains", (True, False): "ends",
                          (False, True): "starts", (False, False): "eq"}[(lead, trail)]
            self.literal = self._fold(core[0])
        else:
            self.shape, self.literal = "general", ""
        toks: list[str] = []
        for it in norm:
            if it in (STAR, QMARK):
                toks.append(it)
            else:
                toks.extend(self._fold(it))
        self.tokens = tuple(toks)

    def _fold(self, s: str) -> str:
        return s if self.case_sensitive else s.lower()

    def __repr__(self) -> str:
        return "GlobPattern(%r)" % "".join("*" if i == STAR else "?" if i == QMARK else i for i in self.items)

    # ------------------------------------------------------------------
    def match_int(self, value: PStr) -> int:
        """Like :meth:`match`, but returns 0/1/2 (FALSE/UNKNOWN/TRUE) for speed."""
        text = value._text
        if text is not None:
            return 2 if self.regex.fullmatch(text) else 0
        return int(self.match(value))

    def match(self, value: PStr) -> Tri:
        if not value.has_gap:
            return Tri.TRUE if self.regex.fullmatch(value.text) else Tri.FALSE
        parts = [p if p is GAP else self._fold(p) for p in value.parts]
        must, may = self._match_partial(parts)
        if must:
            return Tri.TRUE
        return Tri.UNKNOWN if may else Tri.FALSE

    def _match_partial(self, parts: list[str | None]) -> tuple[bool, bool]:
        lit = self.literal
        shape = self.shape
        if shape == "any":
            return True, True
        if shape == "empty":
            return False, all(p is GAP for p in parts)
        if shape == "contains":
            must = any(p is not GAP and lit in p for p in parts)
            return must, True
        if shape == "starts":
            first = parts[0]
            if first is GAP:
                return False, True
            if len(first) >= len(lit):
                ok = first.startswith(lit)
                return ok, ok
            return False, lit.startswith(first)  # a gap follows the first part
        if shape == "ends":
            last = parts[-1]
            if last is GAP:
                return False, True
            if len(last) >= len(lit):
                ok = last.endswith(lit)
                return ok, ok
            return False, lit.endswith(last)
        if shape == "eq":
            rx = "".join(".*" if p is GAP else re.escape(p) for p in parts)
            return False, re.fullmatch(rx, lit, re.S) is not None
        return _dp_match(self.tokens, tuple(parts))


_DP_LIMIT = 400_000


@lru_cache(maxsize=65536)
def _dp_match(tokens: tuple[str, ...], parts: tuple[str | None, ...]) -> tuple[bool, bool]:
    """Exact must/may matching via dynamic programming (general wildcard patterns)."""
    vals: list[str | None] = []
    for p in parts:
        if p is GAP:
            vals.append(GAP)
        else:
            vals.extend(p)
    P, V = len(tokens), len(vals)
    if (P + 1) * (V + 1) > _DP_LIMIT:
        return False, True  # too large: stay sound, answer UNKNOWN
    may = [bytearray(V + 1) for _ in range(P + 1)]
    must = [bytearray(V + 1) for _ in range(P + 1)]
    for i in range(P, -1, -1):
        ti = tokens[i] if i < P else None
        may_i, must_i = may[i], must[i]
        may_n = may[i + 1] if i < P else None
        must_n = must[i + 1] if i < P else None
        for j in range(V, -1, -1):
            if i == P and j == V:
                may_i[j] = must_i[j] = 1
                continue
            vj = vals[j] if j < V else "\x01end"
            if ti == STAR:
                may_i[j] = may_n[j] or (j < V and may_i[j + 1])
                must_i[j] = must_n[j] or (j < V and must_i[j + 1])
            elif j < V and vj is GAP:
                may_i[j] = may_i[j + 1] or (i < P and may_n[j])
                must_i[j] = 0
            elif i < P and j < V and (ti == QMARK or ti == vj):
                may_i[j] = may_n[j + 1]
                must_i[j] = must_n[j + 1]
            else:
                may_i[j] = must_i[j] = 0
    return bool(must[0][0]), bool(may[0][0])


# ---------------------------------------------------------------------------
# Shell-style splitting of partially known command lines
# ---------------------------------------------------------------------------

def tokenize(cmd: PStr) -> list[PStr]:
    """Split a command line into tokens (whitespace, quotes) without interpreting shell operators."""
    segs = shell_segments(cmd, split_operators=False)
    return segs[0][1] if segs else []


def shell_segments(cmd: PStr, split_operators: bool = True) -> list[tuple[PStr, list[PStr]]]:
    """Split a command line into commands (``&&``, ``||``, ``|``, ``;``, ``&``, newline)
    and each command into tokens (whitespace, single/double quotes).

    Returns a list of ``(segment_text, tokens)``. Unknown parts stay inside the token
    they are adjacent to. This is an approximation of cmd.exe and POSIX sh behaviour.
    """
    items = cmd.items()
    segments: list[tuple[PStr, list[PStr]]] = []
    seg: list[str | None] = []
    toks: list[PStr] = []
    tok: list[str | None] = []
    tok_started = False
    quote: str | None = None

    def end_token() -> None:
        nonlocal tok, tok_started
        if tok or tok_started:
            toks.append(PStr(tok))
        tok, tok_started = [], False

    def end_segment() -> None:
        nonlocal seg, toks
        end_token()
        text = PStr(seg).strip()
        if not text.is_empty and toks:
            segments.append((text, toks))
        seg, toks = [], []

    i = 0
    n = len(items)
    while i < n:
        c = items[i]
        if c is GAP:
            tok.append(GAP)
            seg.append(GAP)
            i += 1
            continue
        if quote:
            if c == quote:
                quote = None
            else:
                tok.append(c)
            seg.append(c)
            i += 1
            continue
        if c in "\"'":
            quote = c
            tok_started = True
            seg.append(c)
            i += 1
            continue
        if c.isspace() and c != "\n":
            end_token()
            seg.append(c)
            i += 1
            continue
        if c in "&|;\n" and split_operators:
            prev = items[i - 1] if i > 0 else None
            nxt = items[i + 1] if i + 1 < n else None
            if c == "&" and (prev == ">" or nxt == ">"):  # redirections like 2>&1, &>
                tok.append(c)
                seg.append(c)
                i += 1
                continue
            end_segment()
            i += 2 if nxt == c and c in "&|" else 1
            continue
        tok.append(c)
        seg.append(c)
        i += 1
    end_segment()
    return segments
