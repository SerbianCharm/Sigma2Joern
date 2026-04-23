# Sigma2Joern converter

This repository contains a converter to transform Sigma rules directly into executable Joern scripts.

## Requirements

* Joern (installed and available in your system PATH)
* Python 3
* Python package `pyyaml` (for the Sigma converter)

Install dependencies:

```bash
pip install pyyaml
chmod +x sigma2joern.py
```

## Usage

### 1. Convert Sigma Rules

Convert an existing Sigma rule (.yml) into a Joern script (.sc):

```bash
./sigma2joern.py sigma_rule.yml -o joern_script.sc
```

### 2. Analyze Code in Joern

First, create a Code Property Graph (CPG) from your source code and then apply a script (generated or from this repository):

```bash
# 1. Generate CPG (creates a cpg.bin file)
joern-parse source_code.c
or
joern-scan source_code.c

# 2. Apply script to the graph
joern --script detect_rule.sc --param cpgFile=cpg.bin
```

Alternatively, you can run scripts in the interactive Joern console using:

```bash
cpg.runScript("script.sc")
```
## License

This project is licensed under the MIT License.
