import random
import re

import pytest

from sigma2joern.pstring import GAP, QMARK, STAR, GlobPattern, PStr, Tri, shell_segments, tokenize


def P(*parts):
    return PStr(parts)


def test_pstr_normalizes_parts():
    assert P("a", "b", GAP, GAP, "", "c").parts == ("ab", GAP, "c")
    assert (PStr.known("x") + PStr.unknown() + "y").render() == "x\u00ab\u2026\u00bby"
    assert PStr.join(" ", [PStr.known("a"), PStr.unknown()]).parts == ("a ", GAP)


def test_kleene_logic():
    T, U, F = Tri.TRUE, Tri.UNKNOWN, Tri.FALSE
    assert (T & U) is U and (F & U) is F and (T | U) is T and (F | U) is U
    assert ~U is U and ~T is F


@pytest.mark.parametrize("pattern,value,expected", [
    (["foo"], P("foo"), Tri.TRUE),
    (["FOO"], P("foo"), Tri.TRUE),                       # case-insensitive by default
    ([STAR, "\\whoami.exe"], P(GAP, "\\whoami.exe"), Tri.TRUE),
    ([STAR, "\\whoami.exe"], P(GAP, "whoami.exe"), Tri.UNKNOWN),   # gap could end with "\" or not
    ([STAR, "\\whoami.exe"], P(GAP, "\\cmd.exe"), Tri.FALSE),
    ([STAR, " -enc", STAR], P("powershell -enc ", GAP), Tri.TRUE),
    ([STAR, " -enc", STAR], P("powershell -nop ", GAP), Tri.UNKNOWN),  # the gap may contain it
    ([STAR, " -enc", STAR], P("powershell -nop"), Tri.FALSE),
    (["C:\\Windows\\", STAR], P(GAP, "\\cmd.exe"), Tri.UNKNOWN),
    (["C:\\Windows\\", STAR], P("D:\\", GAP), Tri.FALSE),
    (["C:\\Windows\\", STAR], P("C:\\Win", GAP), Tri.UNKNOWN),
    (["cmd.exe"], P("cmd", GAP), Tri.UNKNOWN),
    (["cmd.exe"], P("pow", GAP), Tri.FALSE),
    ([STAR, "a", STAR, "b", STAR], P("xa", GAP, "bx"), Tri.TRUE),
    ([STAR, "ab", STAR], P("xa", GAP, "bx"), Tri.UNKNOWN),        # must not be split by a gap
    ([STAR], P(GAP), Tri.TRUE),
    ([], P(GAP), Tri.UNKNOWN),
])
def test_glob_matching(pattern, value, expected):
    assert GlobPattern(pattern).match(value) is expected


def test_case_sensitive_pattern():
    assert GlobPattern(["Foo"], case_sensitive=True).match(P("foo")) is Tri.FALSE


def _concretize(value: PStr, rnd: random.Random, alphabet: str) -> str:
    return "".join("".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 4))) if p is GAP else p
                   for p in value.parts)


def test_soundness_against_random_concretizations():
    """TRUE must hold for every concretization, FALSE for none (property test)."""
    rnd = random.Random(7)
    alphabet = "ab\\ "
    for _ in range(3000):
        pat = []
        for _ in range(rnd.randint(1, 4)):
            r = rnd.random()
            pat.append(STAR if r < 0.3 else QMARK if r < 0.4 else "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 2))))
        val = P(*[GAP if rnd.random() < 0.35 else "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 3)))
                  for _ in range(rnd.randint(1, 4))])
        g = GlobPattern(pat)
        result = g.match(val)
        rx = re.compile("".join(".*" if t == STAR else "." if t == QMARK else re.escape(t) for t in g.items), re.S | re.I)
        samples = {_concretize(val, rnd, alphabet) for _ in range(40)}
        outcomes = {bool(rx.fullmatch(s)) for s in samples}
        if result is Tri.TRUE:
            assert outcomes == {True}, (pat, val)
        elif result is Tri.FALSE:
            assert outcomes == {False}, (pat, val)


def test_shell_segments_split_operators_and_quotes():
    segs = shell_segments(PStr.known('curl -s "http://x/a b" | sh && echo "a|b"; id'))
    assert [s.render() for s, _ in segs] == ['curl -s "http://x/a b"', "sh", 'echo "a|b"', "id"]
    assert [t.render() for t in segs[0][1]] == ["curl", "-s", "http://x/a b"]
    assert [t.render() for t in segs[2][1]] == ["echo", "a|b"]


def test_shell_segments_keep_redirections():
    segs = shell_segments(PStr.known("whoami 2>&1 > out.txt"))
    assert len(segs) == 1 and [t.text for t in segs[0][1]] == ["whoami", "2>&1", ">", "out.txt"]


def test_tokenize_without_operators():
    assert [t.text for t in tokenize(PStr.known("cmd /c a & b"))] == ["cmd", "/c", "a", "&", "b"]


def test_gaps_stay_inside_tokens():
    toks = tokenize(P("powershell -enc ", GAP))
    assert toks[-1].parts == (GAP,)
