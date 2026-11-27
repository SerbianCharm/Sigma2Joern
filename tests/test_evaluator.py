import textwrap

from sigma.collection import SigmaCollection

from conftest import RULES_DIR
from sigma2joern.evaluator import LoadedRule, evaluate, load_rules
from sigma2joern.pstring import GAP, PStr, Tri


def rule(detection: str, product: str = "windows") -> LoadedRule:
    det = textwrap.indent(textwrap.dedent(detection).strip("\n"), "    ")
    text = (f"title: t\nlogsource:\n    category: process_creation\n    product: {product}\n"
            f"detection:\n{det}\nlevel: high\n")
    r = SigmaCollection.from_yaml(text).rules[0]
    return LoadedRule(r, "inline", [c.parsed for c in r.detection.parsed_condition], (product,))


def ev(cmdline, image="C:\\Windows\\System32\\cmd.exe", **extra):
    fields = {"Image": image if isinstance(image, PStr) else PStr.known(image),
              "CommandLine": cmdline if isinstance(cmdline, PStr) else PStr.known(cmdline)}
    fields.update({k: PStr.known(v) for k, v in extra.items()})
    return fields


def test_condition_string_is_not_an_indicator():
    r = rule("""
    selection:
        CommandLine|contains: 'vssadmin'
    condition: selection
    """)
    assert evaluate(r, ev("echo selection")).level is None   # the old converter matched this
    assert evaluate(r, ev("vssadmin delete shadows")).level == "match"


def test_filters_exclude_instead_of_include():
    r = rule("""
    selection:
        Image|endswith: '\\cmd.exe'
    filter:
        CommandLine|contains: 'legit_tool'
    condition: selection and not filter
    """)
    assert evaluate(r, ev("cmd /c legit_tool --update")).level is None
    assert evaluate(r, ev("cmd /c whoami")).level == "match"


def test_and_semantics_of_field_maps_and_all_modifier():
    r = rule("""
    selection:
        Image|endswith: '\\reg.exe'
        CommandLine|contains|all:
            - ' add '
            - '\\CurrentVersion\\Run'
    condition: selection
    """)
    assert evaluate(r, ev("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x",
                          image="C:\\Windows\\System32\\reg.exe")).level == "match"
    assert evaluate(r, ev("reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                          image="C:\\Windows\\System32\\reg.exe")).level is None
    assert evaluate(r, ev("reg add HKCU\\x")).level is None  # wrong image


def test_windash_and_base64offset_modifiers():
    r = rule("""
    selection:
        CommandLine|contains|windash: ' -enc '
    condition: selection
    """)
    assert evaluate(r, ev("powershell /enc AAA")).level == "match"
    r2 = rule("""
    selection:
        CommandLine|base64offset|contains: 'IEX'
    condition: selection
    """)
    import base64
    assert evaluate(r2, ev("powershell -e " + base64.b64encode(b"IEX(New-Object Net.WebClient)").decode())).level == "match"


def test_unknown_context_levels():
    r = rule("""
    selection:
        Image|endswith: '\\powershell.exe'
    filter:
        ParentImage|endswith: '\\explorer.exe'
    condition: selection and not filter
    """)
    res = evaluate(r, ev("powershell -nop", image="C:\\x\\powershell.exe"))
    assert res.strict is Tri.UNKNOWN and res.level == "conditional" and res.unknown_fields == {"ParentImage"}
    # a known parent resolves it
    assert evaluate(r, ev("powershell", image="C:\\x\\powershell.exe", ParentImage="C:\\app\\app.exe")).level == "match"
    assert evaluate(r, ev("powershell", image="C:\\x\\powershell.exe", ParentImage="C:\\Windows\\explorer.exe")).level is None

    r2 = rule("""
    selection:
        ParentImage|endswith: '\\winword.exe'
        Image|endswith: '\\cmd.exe'
    condition: selection
    """)
    assert evaluate(r2, ev("cmd /c x")).level == "possible"


def test_partial_command_lines():
    r = rule("""
    selection:
        CommandLine|contains: ' -EncodedCommand '
    condition: selection
    """)
    assert evaluate(r, ev(PStr(("powershell -EncodedCommand ", GAP)))).level == "match"
    assert evaluate(r, ev(PStr(("powershell ", GAP)))).level == "possible"
    assert evaluate(r, ev(PStr(("git status",)))).level is None


def test_regex_on_partial_values():
    r = rule("""
    selection:
        CommandLine|re: '(curl|wget)\\s.*\\|\\s*(ba)?sh\\b'
    condition: selection
    """, product="linux")
    assert evaluate(r, ev(PStr(("sh -c curl http://x | bash",)))).level == "match"
    assert evaluate(r, ev(PStr((GAP, " curl http://x | bash")))).level == "match"
    assert evaluate(r, ev(PStr(("curl http://x | ba", GAP)))).level == "possible"   # \b depends on the gap
    r2 = rule("""
    selection:
        CommandLine|re: '^curl'
    condition: selection
    """, product="linux")
    assert evaluate(r2, ev(PStr((GAP, "curl x")))).level == "possible"              # anchor after a gap


def test_keywords_and_exists():
    r = rule("""
    keywords:
        - 'mimikatz'
    condition: keywords
    """)
    assert evaluate(r, ev("mimikatz.exe privilege::debug")).level == "match"
    assert evaluate(r, ev("whoami")).level == "possible"  # other (unknown) fields might contain it


def test_load_rules_skips_other_log_sources():
    rules, stats = load_rules([RULES_DIR])
    assert stats.loaded == 7 and not stats.errors
    assert all(r.rule.logsource.category == "process_creation" for r in rules)
