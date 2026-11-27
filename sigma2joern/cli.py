"""Command line interface.

    sigma2joern extract --cpg cpg.bin -o events.json        # run the Joern extractor
    sigma2joern match events.json -r rules/                  # evaluate Sigma rules
    sigma2joern scan --src ./project -r rules/               # both steps
    sigma2joern events events.json                           # show the synthetic process events
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from importlib import resources
from pathlib import Path

from . import __version__
from .evaluator import LEVELS, load_rules
from .events import PLATFORMS, build_events
from .matcher import LEVEL_RANK, match_events
from .report import events_to_text, to_json, to_sarif, to_text


def extractor_script() -> Path:
    return Path(str(resources.files("sigma2joern") / "joern" / "extract_events.sc"))


def run_extractor(cpg: str | None, src: str | None, out: str, joern: str, extra: list[str]) -> None:
    exe = shutil.which(joern) or (joern if os.path.exists(joern) else None)
    if exe is None:
        raise SystemExit(f"error: Joern executable '{joern}' not found (install Joern or pass --joern PATH)")
    cmd = [exe, "--script", str(extractor_script()), "--param", f"outFile={os.path.abspath(out)}"]
    if cpg:
        cmd += ["--param", f"cpgFile={os.path.abspath(cpg)}"]
    else:
        cmd += ["--param", f"inputPath={os.path.abspath(src)}"]  # type: ignore[arg-type]
    for item in extra:
        cmd += ["--param", item]
    print("running:", " ".join(cmd), file=sys.stderr)
    proc = subprocess.run(cmd)  # no shell: arguments are passed as a list
    if proc.returncode != 0 or not os.path.exists(out):
        raise SystemExit(f"error: Joern extractor failed (exit code {proc.returncode})")


def _load_events(path: str):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("tool") != "sigma2joern-extractor":
        raise SystemExit(f"error: {path} was not written by extract_events.sc")
    return build_events(data)


def _context(items: list[str]) -> dict[str, str]:
    ctx: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise SystemExit(f"error: --set expects Field=Value, got {item!r}")
        k, v = item.split("=", 1)
        ctx[k.strip()] = v
    return ctx


def _do_match(events_file: str, args: argparse.Namespace) -> int:
    result = _load_events(events_file)
    rules, stats = load_rules(args.rules)
    for path, err in stats.errors[:5]:
        print(f"warning: skipped {path}: {err}", file=sys.stderr)
    if len(stats.errors) > 5:
        print(f"warning: {len(stats.errors) - 5} more rule(s) skipped", file=sys.stderr)
    print(f"{result.calls_matched}/{result.calls_total} candidate calls are process starts -> "
          f"{len(result.events)} synthetic event(s); {stats.loaded} process_creation rule(s) loaded "
          f"from {stats.files} file(s)", file=sys.stderr)
    findings = match_events(result.events, rules, min_level=args.min_level,
                            platforms=args.platform or PLATFORMS, context=_context(args.set),
                            assume_path=not args.no_path_assumption)
    out = {"text": to_text, "json": to_json, "sarif": to_sarif}[args.format](findings)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(out)
    if args.fail_on and any(LEVEL_RANK[f.level] >= LEVEL_RANK[args.fail_on] for f in findings):
        return 1
    return 0


def _add_match_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("-r", "--rules", action="append", required=True,
                   help="Sigma rule file or directory (repeatable)")
    p.add_argument("--min-level", choices=LEVELS, default="conditional",
                   help="lowest confidence to report (default: conditional)")
    p.add_argument("--platform", action="append", choices=PLATFORMS,
                   help="only evaluate rules for this platform (repeatable)")
    p.add_argument("--set", action="append", default=[], metavar="FIELD=VALUE",
                   help="known runtime context, e.g. ParentImage=C:\\Program Files\\App\\app.exe")
    p.add_argument("--no-path-assumption", action="store_true",
                   help="do not assume that bare Windows system programs (whoami, cmd, ...) run from System32")
    p.add_argument("-f", "--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("-o", "--output", help="write report to file")
    p.add_argument("--fail-on", choices=LEVELS, help="exit with code 1 if a finding has at least this level")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sigma2joern",
        description="Find code locations that would trigger Sigma process_creation rules when executed.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_source(p: argparse.ArgumentParser) -> None:
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--cpg", help="CPG created with joern-parse")
        g.add_argument("--src", help="source directory (Joern builds the CPG)")
        p.add_argument("--joern", default="joern", help="path to the joern executable")
        p.add_argument("--joern-param", action="append", default=[], metavar="KEY=VALUE",
                       help="extra parameter for the extractor, e.g. maxDepth=10")

    p_ex = sub.add_parser("extract", help="run the Joern extractor")
    add_source(p_ex)
    p_ex.add_argument("-o", "--output", default="joern_events.json")

    p_m = sub.add_parser("match", help="evaluate Sigma rules against extracted events")
    p_m.add_argument("events", help="JSON written by extract_events.sc")
    _add_match_options(p_m)

    p_s = sub.add_parser("scan", help="extract + match")
    add_source(p_s)
    p_s.add_argument("--keep-events", help="also save the extracted events to this file")
    _add_match_options(p_s)

    p_e = sub.add_parser("events", help="show the synthetic process events")
    p_e.add_argument("events")
    p_e.add_argument("--platform", action="append", choices=PLATFORMS)

    args = parser.parse_args(argv)

    if args.command == "extract":
        run_extractor(args.cpg, args.src, args.output, args.joern, args.joern_param)
        return 0
    if args.command == "match":
        return _do_match(args.events, args)
    if args.command == "events":
        result = _load_events(args.events)
        print(events_to_text(result.events, args.platform or PLATFORMS))
        return 0
    if args.command == "scan":
        with tempfile.TemporaryDirectory() as tmp:
            out = args.keep_events or os.path.join(tmp, "events.json")
            run_extractor(args.cpg, args.src, out, args.joern, args.joern_param)
            return _do_match(out, args)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
