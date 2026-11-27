"""Synthetic process-creation events derived from code ("static Sysmon").

For every process-creating call site we emulate what an EDR/Sysmon would log at runtime
(event ID 1 on Windows, process_creation on Linux/macOS): ``Image``, ``CommandLine`` and
``OriginalFileName``. Shell invocations produce the shell process *and* the commands it
starts, just like at runtime. Values the code does not reveal stay unknown (gaps).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .pstring import GAP, PStr, shell_segments, tokenize
from .sinks import Argv, Cmdline, Invocation, Shell, classify, language_family
from .values import Resolver

PLATFORMS = ("windows", "linux", "macos")

# How the language runtimes wrap a shell command on Windows (cmd.exe command line).
_WIN_SHELL_TEMPLATES = {
    "python": ('cmd.exe /c "', '"'),
    "js": ('cmd.exe /d /s /c "', '"'),
    "php": ('cmd.exe /s /c "', '"'),
}
_DEFAULT_WIN_SHELL = ("cmd.exe /c ", "")
_COMSPEC_DIR = "C:\\WINDOWS\\system32\\"
# argv[0] used by the runtimes on Linux/macOS: Python and Node pass "/bin/sh", libc system() passes "sh".
_POSIX_SHELL_PREFIX = {"python": "/bin/sh -c ", "js": "/bin/sh -c "}
_DEFAULT_POSIX_SHELL = "sh -c "

_SHELLS_POSIX = {"sh", "bash", "dash", "zsh", "ksh", "ash", "busybox"}
POSIX = ("linux", "macos")

# Where Windows finds well-known system programs that are started by bare name ("whoami").
# Used for the default PATH assumption (disable with --no-path-assumption).
_WIN_DIRS = {
    "powershell": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\",
    "powershell_ise": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\",
    "wmic": "C:\\Windows\\System32\\wbem\\",
    "explorer": "C:\\Windows\\", "regedit": "C:\\Windows\\", "hh": "C:\\Windows\\",
}
_WIN_SYSTEM32 = set("""
arp at attrib auditpol bcdedit bitsadmin cacls certreq certutil choice cipher clip cmd cmdkey cmstp
conhost control cscript curl dcomcnfg defrag diskshadow dism dllhost driverquery esentutl eventcreate
eventvwr expand extrac32 findstr finger fltmc forfiles fsutil ftp gpresult gpupdate hostname icacls
ipconfig klist ksetup logman makecab mmc mofcomp mountvol msdt msiexec mshta msinfo32 nbtstat net net1
netsh netstat nltest notepad nslookup odbcconf pcalua ping pnputil powercfg qprocess query quser qwinsta
reg regini regsvr32 replace robocopy route rpcping rundll32 runas sc schtasks sdbinst secedit setspn setx
sfc shutdown systeminfo takeown tar taskkill tasklist taskmgr timeout tracert tzutil vssadmin w32tm
wbadmin wevtutil where whoami wscript wusa xcopy
""".split())


def system_dir(name: str) -> str | None:
    base = name.lower()
    if base.endswith(".exe"):
        base = base[:-4]
    if base in _WIN_DIRS:
        return _WIN_DIRS[base]
    return "C:\\Windows\\System32\\" if base in _WIN_SYSTEM32 else None


@dataclass(frozen=True)
class Origin:
    file: str
    line: int | None
    code: str
    method: str
    sink: str
    language: str


@dataclass(frozen=True)
class ProcEvent:
    """One emulated process start."""

    kind: str                    # "shell" (the shell process itself), "cmdline" or "argv"
    program: PStr                # executable as written in the code / command
    cmdline: PStr                # command line (for kind "shell": the shell *script*)
    args: tuple[PStr, ...]       # argv (kind "argv")
    origin: Origin
    family: str                  # language family, used for shell command line templates
    via: str = ""                # how the event was derived (e.g. "cmd /c", "sh -c")
    platforms: tuple[str, ...] = PLATFORMS  # platforms this process start can happen on

    # ------------------------------------------------------------------
    def fields(self, platform: str, assume_path: bool = True) -> dict[str, PStr]:
        """Sigma process_creation fields as they would be logged on ``platform``."""
        if self.kind == "shell":
            if platform == "windows":
                pre, post = _WIN_SHELL_TEMPLATES.get(self.family, _DEFAULT_WIN_SHELL)
                if assume_path:  # %COMSPEC% on a default installation
                    image = PStr.known("C:\\Windows\\System32\\cmd.exe")
                    cmdline = PStr.known(_COMSPEC_DIR + pre) + self.cmdline + post
                else:
                    image = PStr([GAP, "\\cmd.exe"])
                    cmdline = PStr([GAP, pre]) + self.cmdline + post
            else:
                image = PStr([GAP, "sh"])  # /bin/sh resolves to dash, bash, ... depending on the distribution
                cmdline = PStr.known(_POSIX_SHELL_PREFIX.get(self.family, _DEFAULT_POSIX_SHELL)) + self.cmdline
        elif self.kind == "argv":
            image = normalize_image(self.program, platform, assume_path)
            cmdline = join_argv(self.args, platform)
        else:
            image = normalize_image(self.program, platform, assume_path)
            cmdline = self.cmdline
        out = {"Image": image, "CommandLine": cmdline}
        if platform == "windows":
            out["OriginalFileName"] = basename(image, "\\")
        return out

    def describe(self) -> str:
        if self.kind == "shell":
            return f"<shell> -c {self.cmdline.render()}"
        if self.kind == "argv":
            return " ".join(a.render() for a in self.args)
        return self.cmdline.render()

    def key(self) -> tuple:
        return (self.kind, self.program, self.cmdline, self.args, self.origin, self.via, self.platforms)


# ---------------------------------------------------------------------------
# rendering helpers
# ---------------------------------------------------------------------------

def basename(path: PStr, sep: str) -> PStr:
    parts = list(path.parts)
    for idx in range(len(parts) - 1, -1, -1):
        p = parts[idx]
        if p is not GAP and (sep in p or "/" in p):
            tail = re.split(r"[\\/]", p)[-1]
            return PStr([tail] + parts[idx + 1:])
    return path


def normalize_image(program: PStr, platform: str, assume_path: bool = True) -> PStr:
    """Turn the program as written ("powershell", "C:/x/y", "/bin/sh") into a logged Image.

    Bare names are resolved through PATH; for well-known Windows system programs the
    default PATH (C:\\Windows\\System32 ...) is assumed unless ``assume_path`` is False."""
    if program.is_empty or program.is_unknown:
        return PStr.unknown()
    if platform == "windows":
        parts = [p if p is GAP else p.replace("/", "\\") for p in program.parts]
        prog = PStr(parts)
        known = "".join(prog.known_parts())
        is_path = "\\" in known or (parts[0] is not GAP and re.match(r"^[A-Za-z]:", parts[0]) is not None)
        last = prog.parts[-1]
        if last is not GAP and "." not in last.rsplit("\\", 1)[-1]:
            prog = prog + ".exe"  # CreateProcess appends .exe when searching the PATH
        if not is_path and prog.parts[0] is not GAP:
            known_dir = system_dir(prog.text) if (assume_path and not prog.has_gap) else None
            prog = PStr.known(known_dir) + prog if known_dir else PStr([GAP, "\\"]) + prog  # PATH lookup
        return prog
    known = "".join(program.known_parts())
    if "/" not in known and program.parts[0] is not GAP:
        return PStr([GAP, "/"]) + program
    return program


def join_argv(args: Iterable[PStr], platform: str) -> PStr:
    rendered: list[PStr] = []
    for a in args:
        if platform == "windows" and any(p is not GAP and re.search(r"\s", p) for p in a.parts):
            rendered.append(PStr.known('"') + a + '"')
        else:
            rendered.append(a)
    return PStr.join(" ", rendered)


# ---------------------------------------------------------------------------
# building events from the extractor output
# ---------------------------------------------------------------------------

def _refine_platforms(platforms: tuple[str, ...], program: PStr, via: str = "") -> tuple[str, ...]:
    """Narrow the platforms using the program path style and how the process was started."""
    hint: tuple[str, ...] | None = None
    first = program.parts[0] if program.parts else GAP
    last = program.parts[-1] if program.parts else GAP
    if via.startswith("cmd"):
        hint = ("windows",)
    elif via and via != "shell" and via.split()[0] in _SHELLS_POSIX:
        hint = POSIX
    elif first is not GAP and first.startswith("/"):
        hint = POSIX
    elif first is not GAP and (re.match(r"^[A-Za-z]:[\\/]", first) or first.startswith("\\\\")):
        hint = ("windows",)
    elif last is not GAP and last.lower().endswith((".exe", ".bat", ".cmd", ".com")):
        hint = ("windows",)
    if hint is None:
        return platforms
    narrowed = tuple(p for p in platforms if p in hint)
    return narrowed or platforms


def _prog_name(token: PStr) -> str | None:
    if token.has_gap or token.is_empty:
        return None
    name = re.split(r"[\\/]", token.text)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _expand_command(cmd: PStr, origin: Origin, family: str, via: str, depth: int,
                    platforms: tuple[str, ...]) -> list[ProcEvent]:
    """Commands executed by a shell: split at &&, ||, |, ;, & and newlines."""
    out: list[ProcEvent] = []
    for seg, tokens in shell_segments(cmd):
        out.extend(_command_event(seg, tokens, origin, family, via, depth, platforms))
    return out


def _command_event(seg: PStr, tokens: list[PStr], origin: Origin, family: str, via: str,
                   depth: int, platforms: tuple[str, ...]) -> list[ProcEvent]:
    own = _refine_platforms(_refine_platforms(platforms, PStr(), via), tokens[0])
    events = [ProcEvent("cmdline", tokens[0], seg, (), origin, family, via, own)]
    if depth >= 3:
        return events
    name = _prog_name(tokens[0])
    lowered = [None if t.has_gap else t.text.lower() for t in tokens]
    if name == "cmd":
        for idx, t in enumerate(lowered[1:], start=1):
            if t in ("/c", "/k", "/r"):
                inner = PStr.join(" ", tokens[idx + 1:])
                events += _expand_command(inner, origin, family, "cmd /c", depth + 1, own)
                break
    elif name in _SHELLS_POSIX:
        for idx, t in enumerate(lowered[1:], start=1):
            if t is not None and re.fullmatch(r"-[a-z]*c[a-z]*", t) and idx + 1 < len(tokens):
                events += _expand_command(tokens[idx + 1], origin, family, f"{name} -c", depth + 1, own)
                break
    return events


def events_for_invocation(inv: Invocation, origin: Origin, family: str,
                          platforms: tuple[str, ...] = PLATFORMS) -> list[ProcEvent]:
    if isinstance(inv, Shell):
        shell_ev = ProcEvent("shell", PStr.unknown(), inv.cmd, (), origin, family, "shell", platforms)
        return [shell_ev] + _expand_command(inv.cmd, origin, family, "shell", 1, platforms)
    if isinstance(inv, Cmdline):
        tokens = tokenize(inv.cmdline)  # no shell involved: operators belong to the arguments
        program = inv.program if inv.program is not None else (tokens[0] if tokens else PStr.unknown())
        own = _refine_platforms(platforms, program)
        ev = ProcEvent("cmdline", program, inv.cmdline, (), origin, family, "", own)
        if tokens:
            return [ev] + _command_event(inv.cmdline, tokens, origin, family, "", 0, own)[1:]
        return [ev]
    if isinstance(inv, Argv):
        program = inv.program if inv.program is not None else (inv.args[0] if inv.args else PStr.unknown())
        own = _refine_platforms(platforms, program)
        ev = ProcEvent("argv", program, PStr(), inv.args, origin, family, "", own)
        extra = _command_event(PStr.join(" ", list(inv.args)), list(inv.args), origin, family, "", 0, own)[1:] \
            if inv.args else []
        return [ev] + extra
    return []


@dataclass
class ExtractionResult:
    events: list[ProcEvent]
    language: str
    calls_total: int
    calls_matched: int
    unmatched_names: dict[str, int] = field(default_factory=dict)


def build_events(data: dict[str, Any]) -> ExtractionResult:
    """Convert the JSON written by ``extract_events.sc`` into synthetic process events."""
    language = data.get("language", "")
    family = language_family(language)
    resolver = Resolver(language)
    events: list[ProcEvent] = []
    seen: set = set()
    matched = 0
    unmatched: dict[str, int] = {}
    for call in data.get("calls", []):
        sink = classify(call, family)
        if sink is None:
            unmatched[call.get("name", "?")] = unmatched.get(call.get("name", "?"), 0) + 1
            continue
        matched += 1
        origin = Origin(
            file=call.get("file", ""), line=call.get("line"), code=(call.get("code") or "")[:300],
            method=call.get("method", ""), sink=sink.label, language=language,
        )
        for inv in sink.build(call, resolver):
            for ev in events_for_invocation(inv, origin, family, sink.platforms or PLATFORMS):
                if ev.key() not in seen:
                    seen.add(ev.key())
                    events.append(ev)
    return ExtractionResult(events, language, len(data.get("calls", [])), matched, unmatched)
