"""End-to-end: extractor JSON (fixtures mirroring examples/samples) -> events -> Sigma findings."""

import json

import builders
import pytest

from conftest import RULES_DIR
from sigma2joern.cli import main
from sigma2joern.evaluator import load_rules
from sigma2joern.events import build_events
from sigma2joern.matcher import match_events

EXPECTED = {
    "python": {("Test - Whoami Privilege Discovery", 17, "match"),
               ("Test - Certutil Download", 13, "match"),
               ("Test - Encoded PowerShell Not Started By Explorer", 24, "conditional")},
    "c": {("Test - Whoami Privilege Discovery", 19, "match"),
          ("Test - Download Piped To Shell", 23, "match"),
          ("Test - Scheduled Task Creation", 12, "conditional")},
    "java": {("Test - Run Key Persistence Via Reg.exe", 8, "match")},
    "js": {("Test - Download Piped To Shell", 7, "match"),
           ("Test - Linux Discovery Commands", 11, "match")},
}


@pytest.fixture(scope="module")
def rules():
    return load_rules([RULES_DIR])[0]


@pytest.mark.parametrize("lang", sorted(EXPECTED))
def test_samples(lang, rules):
    events = build_events(builders.ALL_SAMPLES[lang]()).events
    found = {(f.rule.title, f.event.origin.line, f.level) for f in match_events(events, rules)}
    assert found == EXPECTED[lang]


def test_cli_json_and_sarif(tmp_path, capsys):
    events_file = tmp_path / "events.json"
    events_file.write_text(json.dumps(builders.java_sample()))
    assert main(["match", str(events_file), "-r", RULES_DIR, "-f", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["findings"][0]["rule"]["title"] == "Test - Run Key Persistence Via Reg.exe"
    assert out["findings"][0]["location"]["line"] == 8

    sarif_file = tmp_path / "out.sarif"
    assert main(["match", str(events_file), "-r", RULES_DIR, "-f", "sarif", "-o", str(sarif_file),
                 "--fail-on", "match"]) == 1
    sarif = json.loads(sarif_file.read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"]["region"]["startLine"] == 8


def test_cli_context_resolves_unknown_fields(tmp_path, capsys):
    events_file = tmp_path / "events.json"
    events_file.write_text(json.dumps(builders.python_sample()))
    main(["match", str(events_file), "-r", RULES_DIR, "-f", "json", "--set", "ParentImage=C:\\Windows\\explorer.exe"])
    titles = {f["rule"]["title"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert "Test - Encoded PowerShell Not Started By Explorer" not in titles
