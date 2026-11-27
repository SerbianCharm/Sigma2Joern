import pytest

from builders import assign, ident, js_array, lit, op, other, writer
from sigma2joern.pstring import GAP, PStr
from sigma2joern.values import Resolver, decode_literal


@pytest.mark.parametrize("code,lang,expected", [
    ('"C:\\\\Users\\\\Public"', "PYTHONSRC", "C:\\Users\\Public"),
    ("r'C:\\Temp\\x'", "PYTHONSRC", "C:\\Temp\\x"),
    ("powershell -enc ", "PYTHONSRC", "powershell -enc "),        # f-string part without quotes
    ('"a\\tb"', "JAVASRC", "a\tb"),
    ('"\\\\\\\\?\\\\GLOBALROOT"', "JAVASRC", "\\\\?\\GLOBALROOT"),
    ("'it\\'s'", "PHP", "it's"),
    ('"a" "b"', "NEWC", "ab"),                                   # adjacent C literals
    ('L"wide\\\\x"', "NEWC", "wide\\x"),
    ('"\\d"', "JSSRC", "d"),                                     # JS drops unknown escapes
    ("`raw\\n`", "GOLANG", "raw\\n"),
    ('@"C:\\Temp"', "CSHARPSRC", "C:\\Temp"),
    ("42", "JAVASRC", "42"),
])
def test_decode_literal(code, lang, expected):
    assert decode_literal(code, lang) == expected


def test_concatenation_and_unknown_parts():
    r = Resolver("JAVASRC")
    expr = op("<operator>.addition", lit('"cmd /c "'), ident("userInput"))
    assert r.string(expr) == [PStr(("cmd /c ", GAP))]


def test_python_fstring_and_format():
    r = Resolver("PYTHONSRC")
    fstr = op("<operator>.formatString", lit("ping -n 1 "), op("<operator>.formattedValue", ident("host")))
    assert r.string(fstr)[0].parts == ("ping -n 1 ", GAP)
    fmt = op("format", lit('"{} /c {}"'), instance=lit('"{} /c {}"'))
    fmt["args"] = [{"i": 0, "n": None, "v": lit('"{} /c {}"')},
                   {"i": 1, "n": None, "v": lit('"cmd"')}, {"i": 2, "n": None, "v": lit('"whoami"')}]
    assert r.string(fmt)[0].text == "cmd /c whoami"


def test_python_percent_formatting():
    r = Resolver("PYTHONSRC")
    expr = op("<operator>.modulo", lit('"net user %s %s /add"'),
              op("<operator>.tupleLiteral", lit('"bob"'), ident("pw")))
    assert r.string(expr)[0].parts == ("net user bob ", GAP, " /add")


def test_assignment_replay_with_append():
    r = Resolver("PYTHONSRC")
    cmd = ident("cmd", defs=[assign(lit('"net group"'), 1),
                             assign(lit("' \"domain admins\" /domain'"), 2, op="<operator>.assignmentPlus")])
    assert r.string(cmd)[0].text == 'net group "domain admins" /domain'


def test_parameter_values_come_from_callers():
    r = Resolver("PYTHONSRC")
    p = ident("url", param_index=1, callers=[lit('"http://a"'), lit('"http://b"')])
    assert {v.text for v in r.string(p)} == {"http://a", "http://b"}


def test_c_buffer_writes():
    r = Resolver("NEWC")
    buf = ident("buf", writers=[writer("strcpy", 1, lit('"cmd.exe /c "')), writer("strcat", 2, ident("arg"))])
    assert r.string(buf)[0].parts == ("cmd.exe /c ", GAP)
    buf2 = ident("b", writers=[writer("snprintf", 1, lit("sizeof(b)"), lit('"%s -enc %s"'), lit('"powershell"'), ident("x"))])
    assert r.string(buf2)[0].parts == ("powershell -enc ", GAP)
    buf3 = ident("b", writers=[writer("sprintf_s", 1, lit("64"), lit('"ping %d.%d"'), lit("10"), ident("n"))])
    assert r.string(buf3)[0].parts == ("ping 10.", GAP)


def test_lists_python_java_js():
    assert [v.text for v in Resolver("PYTHONSRC").string_list(op("<operator>.listLiteral", lit('"a"'), lit('"b"')))] == ["a", "b"]
    assert [v.text for v in Resolver("JAVASRC").string_list(op("asList", lit('"x"'), lit('"y"')))] == ["x", "y"]
    assert [v.text for v in Resolver("JSSRC").string_list(js_array(lit("'-c'"), lit("'id'")))] == ["-c", "id"]
    argv = op("<operator>.arrayInitializer", lit('"sh"'), lit('"-c"'), lit('"id"'), lit("NULL"))
    assert [v.text for v in Resolver("NEWC").string_list(argv)] == ["sh", "-c", "id"]


def test_join_of_list():
    r = Resolver("PYTHONSRC")
    join = op("join", op("<operator>.listLiteral", lit('"cmd"'), lit('"/c"'), lit('"dir"')), instance=lit('" "'))
    assert r.string(join)[0].text == "cmd /c dir"


def test_cycles_and_unknown_nodes_do_not_crash():
    r = Resolver("JAVASRC")
    x = ident("x")
    x["defs"] = [assign(op("<operator>.addition", {"k": "cut", "code": "x"}, lit('"a"')), 1)]
    assert r.string(x)[0].parts == (GAP, "a")
    assert r.string(other("foo()"))[0].parts == (GAP,)
