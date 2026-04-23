#!/usr/bin/env python3
import yaml
import argparse
import sys
import os

def extract_keywords(node, keywords):
    if isinstance(node, dict):
        for k, v in node.items():
            extract_keywords(v, keywords)
    elif isinstance(node, list):
        for item in node:
            extract_keywords(item, keywords)
    elif isinstance(node, str):
        if len(node) > 2 and not node.startswith('*'):
            keywords.add(node.replace('"', '\\"'))

def generate_scala(title, description, keywords, output_path):
    scala_code = f"""import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.cpgloading.CpgLoader

@main def exec(cpgFile: String): Unit = {{
  println(s"Loading CPG from: $cpgFile ...")
  val cpg = CpgLoader.load(cpgFile)
  
  println("Sigma Rule Conversion: {title}")
  println("Description: {description}")
  println("Searching for system calls that might trigger the following indicators...")
  
  val indicators = Set(
    {', '.join([f'"{kw}"' for kw in keywords])}
  )

  val findings = cpg.call
    .filter(call => call.name.matches(".*(system|exec|popen|Runtime\\\\.exec).*"))
    .filter {{ call =>
      val argsCode = call.argument.code.l.mkString(" ").toLowerCase
      indicators.exists(indicator => argsCode.contains(indicator.toLowerCase))
    }}
    .map {{ call =>
      val line = call.lineNumber.getOrElse(-1)
      val filename = call.location.filename
      val code = call.code
      (filename, line, code)
    }}
    .l

  if (findings.isEmpty) {{
    println("No matches found for the Sigma indicators.")
  }} else {{
    println(s"\\n${{findings.size}} critical system calls found:\\n")
    findings.foreach {{ case (filename, line, code) =>
      val lineStr = if (line == -1) "N/A" else line.toString
      println(s"File: $filename | Line: $lineStr")
      println(s"Code:  $code")
      println("-" * 50)
    }}
  }}
}}
"""
    with open(output_path, 'w') as f:
        f.write(scala_code)
    print(f"[+] Joern script successfully created: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Converts simple Sigma rules into Joern .sc scripts.")
    parser.add_argument("sigma_file", help="Path to the Sigma YAML file")
    parser.add_argument("-o", "--output", help="Output file (e.g., rule.sc)", default="sigma_rule.sc")
    
    args = parser.parse_args()

    if not os.path.exists(args.sigma_file):
        print(f"[-] Error: File {args.sigma_file} not found.")
        sys.exit(1)

    try:
        with open(args.sigma_file, 'r') as f:
            rule = yaml.safe_load(f)
    except Exception as e:
        print(f"[-] Error parsing the YAML file: {e}")
        sys.exit(1)

    title = rule.get('title', 'Unknown Rule')
    description = rule.get('description', 'N/A').replace('\n', ' ')
    
    keywords = set()
    if 'detection' in rule:
        extract_keywords(rule['detection'], keywords)
    
    if not keywords:
        print("[-] No usable indicators found in the Sigma rule.")
        sys.exit(1)

    generate_scala(title, description, keywords, args.output)

if __name__ == "__main__":
    main()
