"""Process-creation APIs per language and how their arguments map to a process start.

Each sink turns one call site (as exported by ``extract_events.sc``) into one or more
*invocations*:

* ``Shell(cmd)``                 - the command string is run by a shell (system(), shell=True, exec())
* ``Cmdline(program, cmdline)``  - a complete command line without shell (CreateProcess, WinExec)
* ``Argv(program, args)``        - an argument vector (execv, subprocess.run([...]), ProcessBuilder)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .pstring import GAP, PStr
from .values import Resolver

Call = dict[str, Any]


@dataclass(frozen=True)
class Shell:
    cmd: PStr


@dataclass(frozen=True)
class Cmdline:
    program: PStr | None
    cmdline: PStr


@dataclass(frozen=True)
class Argv:
    program: PStr | None
    args: tuple[PStr, ...]


Invocation = Shell | Cmdline | Argv

LANG_FAMILIES = {
    "c": ("NEWC", "C", "CPP", "GHIDRA", "LLVM"),
    "python": ("PYTHONSRC", "PYTHON"),
    "java": ("JAVASRC", "JAVA", "KOTLIN", "JIMPLE"),
    "js": ("JSSRC", "JAVASCRIPT", "TYPESCRIPT"),
    "php": ("PHP",),
    "go": ("GOLANG", "GO"),
    "csharp": ("CSHARPSRC", "CSHARP"),
    "ruby": ("RUBYSRC", "RUBY"),
}


def language_family(language: str) -> str:
    lang = (language or "").upper()
    for fam, names in LANG_FAMILIES.items():
        if lang in names:
            return fam
    for fam, names in LANG_FAMILIES.items():  # e.g. "NEWC_CPP"
        if any(lang.startswith(n) for n in names):
            return fam
    return "unknown"


# ---------------------------------------------------------------------------
# helpers to access call arguments
# ---------------------------------------------------------------------------

def arg(call: Call, index: int) -> dict | None:
    for a in call.get("args", []):
        if a.get("i") == index and not a.get("n"):
            return a.get("v")
    return None


def kwarg(call: Call, name: str) -> dict | None:
    for a in call.get("args", []):
        if a.get("n") == name:
            return a.get("v")
    return None


def positional(call: Call, start: int = 1) -> list[dict]:
    args = [a for a in call.get("args", []) if a.get("i", -1) >= start and not a.get("n")]
    return [a["v"] for a in sorted(args, key=lambda a: a["i"])]


_NULLS = ("NULL", "0", "nullptr", "None", "null", "nil", "(void*)0", "((void *)0)", "(char *)NULL", "(char*)NULL")


def is_null(node: dict | None) -> bool:
    if not node:
        return False
    if node.get("k") == "call" and node.get("name") == "<operator>.cast":  # (char *)NULL
        args = [a for a in node.get("args", []) if a.get("i", 0) >= 1]
        return bool(args) and is_null(max(args, key=lambda a: a["i"])["v"])
    return node.get("k") in ("lit", "id", "other") and node.get("code", "").strip() in _NULLS


def is_true(node: dict | None) -> bool:
    return bool(node) and node.get("k") == "lit" and node.get("code", "").strip() in ("True", "true", "1")


def first_token(cmd: PStr) -> PStr:
    """First whitespace separated token of a command line (quotes respected)."""
    items = cmd.items()
    out: list[str | None] = []
    quote = None
    i = 0
    while i < len(items) and items[i] is not GAP and items[i].isspace():
        i += 1
    for c in items[i:]:
        if c is GAP:
            out.append(GAP)
        elif quote:
            if c == quote:
                quote = None
            else:
                out.append(c)
        elif c in "\"'":
            quote = c
        elif c.isspace():
            break
        else:
            out.append(c)
    return PStr(out)


# ---------------------------------------------------------------------------
# invocation builders
# ---------------------------------------------------------------------------

def _shell(index: int) -> Callable[[Call, Resolver], list[Invocation]]:
    def build(call: Call, r: Resolver) -> list[Invocation]:
        node = arg(call, index)
        lst = r.string_list(node)
        if lst is not None:  # e.g. Ruby system("a", "b") style lists joined by the shell
            return [Shell(PStr.join(" ", lst))]
        return [Shell(v) for v in r.string(node)]
    return build


def _cmdline(app_index: int | None, cmd_index: int) -> Callable[[Call, Resolver], list[Invocation]]:
    def build(call: Call, r: Resolver) -> list[Invocation]:
        app_node = arg(call, app_index) if app_index else None
        cmd_node = arg(call, cmd_index)
        apps = [None] if (app_node is None or is_null(app_node)) else r.string(app_node)
        if cmd_node is None or is_null(cmd_node):
            return [Cmdline(a, a) for a in apps if a is not None] or [Cmdline(None, PStr.unknown())]
        out: list[Invocation] = []
        for a in apps:
            for c in r.string(cmd_node):
                out.append(Cmdline(a if a is not None else first_token(c), c))
        return out
    return build


def _argv_list(prog_index: int | None, list_index: int, prepend_program: bool = False):
    def build(call: Call, r: Resolver) -> list[Invocation]:
        progs = r.string(arg(call, prog_index)) if prog_index else [None]
        lst = r.string_list(arg(call, list_index))
        out: list[Invocation] = []
        for p in progs:
            if lst is None:
                if arg(call, list_index) is None and p is not None:  # no argument list given
                    out.append(Argv(p, (p,)))
                else:
                    base = p if p is not None else PStr.unknown()
                    out.append(Cmdline(p, base + PStr([" ", GAP])))
            else:
                args = ((p,) if prepend_program and p is not None else ()) + tuple(lst)
                out.append(Argv(p if p is not None else (args[0] if args else None), args))
        return out
    return build


def _argv_varargs(prog_index: int | None, start: int, prepend_program: bool = False):
    def build(call: Call, r: Resolver) -> list[Invocation]:
        nodes = positional(call, start)
        args: list[PStr] = []
        for n in nodes:
            if is_null(n):
                break
            lst = r.string_list(n)
            if lst is not None:  # spread list, e.g. exec.Command(name, args...)
                args.extend(lst)
            else:
                args.append(r.string(n)[0])
        progs = r.string(arg(call, prog_index)) if prog_index else [None]
        out: list[Invocation] = []
        for p in progs:
            full = ((p,) if prepend_program and p is not None else ()) + tuple(args)
            if full:
                out.append(Argv(p if p is not None else full[0], full))
        return out
    return build


def _python_subprocess(call: Call, r: Resolver) -> list[Invocation]:
    node = arg(call, 1) or kwarg(call, "args")
    if node is None:
        return []
    shell = is_true(kwarg(call, "shell"))
    name = call.get("name", "")
    lst = r.string_list(node)
    if name in ("getoutput", "getstatusoutput"):
        shell = True
    if lst is not None:
        return [Shell(PStr.join(" ", lst))] if shell else [Argv(lst[0] if lst else None, tuple(lst))]
    vals = r.string(node)
    if shell:
        return [Shell(v) for v in vals]
    return [Cmdline(first_token(v), v) for v in vals]


def _java_exec(call: Call, r: Resolver) -> list[Invocation]:
    node = arg(call, 1)
    lst = r.string_list(node)
    if lst is not None:
        return [Argv(lst[0] if lst else None, tuple(lst))]
    return [Cmdline(first_token(v), v) for v in r.string(node)]


def _java_process_builder(call: Call, r: Resolver) -> list[Invocation]:
    nodes = positional(call, 1)
    if not nodes:
        return []
    if len(nodes) == 1:
        lst = r.string_list(nodes[0])
        if lst is not None:
            return [Argv(lst[0] if lst else None, tuple(lst))]
    args = tuple(r.string(n)[0] for n in nodes)
    return [Argv(args[0], args)]


def _js_spawn(call: Call, r: Resolver) -> list[Invocation]:
    cmd = arg(call, 1)
    lst = r.string_list(arg(call, 2))
    opts = arg(call, 2) if lst is None else arg(call, 3)
    shell_opt = bool(opts) and re.search(r"shell\s*:\s*(true|['\"])", opts.get("code", "")) is not None
    out: list[Invocation] = []
    for c in r.string(cmd):
        full = (c,) + tuple(lst or ())
        if shell_opt:
            out.append(Shell(PStr.join(" ", list(full))))
        else:
            out.append(Argv(c, full))
    return out


def _csharp_start(call: Call, r: Resolver) -> list[Invocation]:
    file_node, args_node = arg(call, 1), arg(call, 2)
    out: list[Invocation] = []
    for f in r.string(file_node):
        if args_node is None:
            out.append(Cmdline(f, f))
        else:
            for a in r.string(args_node):
                out.append(Cmdline(f, f + " " + a))
    return out


def _shell_execute(call: Call, r: Resolver) -> list[Invocation]:
    file_node, params_node = arg(call, 3), arg(call, 4)
    out: list[Invocation] = []
    for f in r.string(file_node):
        if params_node is None or is_null(params_node):
            out.append(Cmdline(f, f))
        else:
            for p in r.string(params_node):
                out.append(Cmdline(f, f + " " + p))
    return out


def _ruby_system(call: Call, r: Resolver) -> list[Invocation]:
    nodes = positional(call, 1)
    if nodes and nodes[0].get("k") == "call" and "{" in nodes[0].get("code", "")[:1]:
        nodes = nodes[1:]  # leading env hash
    if len(nodes) == 1:
        return [Shell(v) for v in r.string(nodes[0])]
    args = tuple(r.string(n)[0] for n in nodes)
    return [Argv(args[0], args)] if args else []


# ---------------------------------------------------------------------------
# sink table
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Sink:
    label: str
    family: str
    names: str                     # regex (full match) on the call name
    build: Callable[[Call, Resolver], list[Invocation]]
    context: str | None = None     # regex (search) on fullName/code/receiver; required if set
    exclude: str | None = None     # regex (search) on code/receiver; rejects if found
    bare_ok: bool = False          # accept calls without receiver even if context is missing
    platforms: tuple[str, ...] | None = None  # API only exists on these platforms

    def accepts(self, call: Call) -> bool:
        name = call.get("name", "")
        if not re.fullmatch(self.names, name):
            return False
        haystack = " ".join(str(call.get(k) or "") for k in ("fullName", "code", "receiver"))
        if self.exclude and re.search(self.exclude, " ".join(str(call.get(k) or "") for k in ("code", "receiver"))):
            return False
        if self.context is None:
            return True
        if re.search(self.context, haystack):
            return True
        if self.bare_ok:
            recv = (call.get("receiver") or "").strip()
            code = (call.get("code") or "").strip()
            return recv in ("", name) or code.startswith(name + "(")
        return False


SINKS: tuple[Sink, ...] = (
    # ---- C / C++ / binaries ------------------------------------------------------------
    Sink("C shell (system/popen)", "c", r"(std::)?(_w?system|system|_?w?popen|popen)", _shell(1)),
    Sink("WinExec", "c", r"WinExec", _cmdline(None, 1), platforms=("windows",)),
    Sink("CreateProcess", "c", r"CreateProcess[AW]?", _cmdline(1, 2), platforms=("windows",)),
    Sink("CreateProcessAsUser", "c", r"CreateProcessAsUser[AW]?", _cmdline(2, 3), platforms=("windows",)),
    Sink("CreateProcessWithTokenW", "c", r"CreateProcessWithTokenW", _cmdline(3, 4), platforms=("windows",)),
    Sink("CreateProcessWithLogonW", "c", r"CreateProcessWithLogonW", _cmdline(5, 6), platforms=("windows",)),
    Sink("ShellExecute", "c", r"ShellExecute[AW]?", _shell_execute, platforms=("windows",)),
    Sink("exec*l (varargs)", "c", r"execl[pe]?", _argv_varargs(1, 2), platforms=("linux", "macos")),
    Sink("exec*v (argv)", "c", r"execv(p|e|pe)?", _argv_list(1, 2), platforms=("linux", "macos")),
    Sink("_exec*l (varargs)", "c", r"_w?execl[pe]?", _argv_varargs(1, 2), platforms=("windows",)),
    Sink("_exec*v (argv)", "c", r"_w?execv(p|e|pe)?", _argv_list(1, 2), platforms=("windows",)),
    Sink("posix_spawn", "c", r"posix_spawnp?", _argv_list(2, 5), platforms=("linux", "macos")),
    Sink("_spawn*l (varargs)", "c", r"_?w?spawnl[pe]?", _argv_varargs(2, 3), platforms=("windows",)),
    Sink("_spawn*v (argv)", "c", r"_?w?spawnv(p|e|pe)?", _argv_list(2, 3), platforms=("windows",)),
    # ---- Python ---------------------------------------------------------------------------
    Sink("os.system/os.popen", "python", r"system|popen", _shell(1),
         context=r"(^|\W)os(\.py)?[.:]|os\.(system|popen)", exclude=r"self\.|cls\.", bare_ok=True),
    Sink("subprocess", "python", r"run|call|check_call|check_output|Popen|getoutput|getstatusoutput",
         _python_subprocess, context=r"subprocess"),
    Sink("subprocess (imported names)", "python", r"Popen|check_call|check_output|getoutput|getstatusoutput",
         _python_subprocess, exclude=r"self\.|cls\."),
    Sink("os.exec*l", "python", r"execl[p]?e?", _argv_varargs(1, 2), context=r"(^|\W)os[.:]|os\.py", bare_ok=True),
    Sink("os.exec*v", "python", r"execv[p]?e?", _argv_list(1, 2), context=r"(^|\W)os[.:]|os\.py", bare_ok=True),
    Sink("os.spawn*l", "python", r"spawnl[p]?e?", _argv_varargs(2, 3), context=r"(^|\W)os[.:]|os\.py", bare_ok=True),
    Sink("os.spawn*v", "python", r"spawnv[p]?e?", _argv_list(2, 3), context=r"(^|\W)os[.:]|os\.py", bare_ok=True),
    Sink("os.startfile", "python", r"startfile", _cmdline(None, 1), context=r"(^|\W)os[.:]|os\.py", bare_ok=True,
         platforms=("windows",)),
    Sink("asyncio.create_subprocess_shell", "python", r"create_subprocess_shell", _shell(1)),
    Sink("asyncio.create_subprocess_exec", "python", r"create_subprocess_exec", _argv_varargs(None, 1)),
    Sink("pty.spawn", "python", r"spawn", _java_exec, context=r"(^|\W)pty[.:]|pty\.py"),
    # ---- Java / Kotlin --------------------------------------------------------------------
    Sink("Runtime.exec", "java", r"exec", _java_exec, context=r"java\.lang\.Runtime\.exec|getRuntime\(\)"),
    Sink("ProcessBuilder", "java", r"<init>|command", _java_process_builder,
         context=r"java\.lang\.ProcessBuilder\.(<init>|command)|new ProcessBuilder"),
    # ---- JavaScript / TypeScript (Node.js) ----------------------------------------------------
    Sink("child_process.exec", "js", r"exec|execSync", _shell(1),
         context=r"child_process|childProcess|(^|\W)(cp|child|proc|shell)\.exec",
         exclude=r"(?i)\b(re|regex|regexp|rx|pattern)\.exec\b|/[gimsuy]*\.exec\b", bare_ok=True),
    Sink("child_process.execFile", "js", r"execFile|execFileSync", _argv_list(1, 2, prepend_program=True),
         context=r"child_process|childProcess|(^|\W)(cp|child|proc)\.", bare_ok=True),
    Sink("child_process.spawn", "js", r"spawn|spawnSync", _js_spawn,
         context=r"child_process|childProcess|(^|\W)(cp|child|proc)\.", bare_ok=True),
    # ---- PHP ------------------------------------------------------------------------------------
    Sink("PHP shell functions", "php", r"exec|system|passthru|shell_exec|popen|proc_open|<operator>\.shellExec",
         _shell(1), exclude=r"->|::"),
    Sink("pcntl_exec", "php", r"pcntl_exec", _argv_list(1, 2, prepend_program=True)),
    # ---- Go -------------------------------------------------------------------------------------
    Sink("exec.Command", "go", r"Command", _argv_varargs(1, 2, prepend_program=True), context=r"os/exec|(^|\W)exec\.Command"),
    Sink("exec.CommandContext", "go", r"CommandContext", _argv_varargs(2, 3, prepend_program=True),
         context=r"os/exec|(^|\W)exec\.CommandContext"),
    Sink("syscall.Exec", "go", r"Exec", _argv_list(1, 2), context=r"syscall"),
    # ---- C# -------------------------------------------------------------------------------------
    Sink("Process.Start", "csharp", r"Start", _csharp_start, context=r"System\.Diagnostics\.Process\.Start|Process\.Start"),
    # ---- Ruby -----------------------------------------------------------------------------------
    Sink("Kernel#system/exec/spawn", "ruby", r"system|exec|spawn|capture2e?|capture3|popen[23]e?",
         _ruby_system, context=r"Open3|Kernel|Process", bare_ok=True),
)


def classify(call: Call, family: str) -> Sink | None:
    for sink in SINKS:
        if sink.family == family and sink.accepts(call):
            return sink
    return None


def candidate_name_regex(families: Iterable[str] | None = None) -> str:
    """Regex for the Joern extractor that pre-selects candidate calls by name."""
    names = sorted({s.names for s in SINKS if families is None or s.family in families})
    return "(" + "|".join(f"(?:{n})" for n in names) + ")"
