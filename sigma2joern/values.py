"""Reconstruct (partially known) string values from the value trees exported by
``joern/extract_events.sc``.

A value tree describes how an argument is built: literals, identifiers with their
reaching assignments, parameters with the arguments of their call sites, string
concatenation, f-strings/template literals, ``printf``-style formatting, lists etc.
Everything that cannot be evaluated statically becomes a gap in a :class:`PStr`.
"""

from __future__ import annotations

import ast
import itertools
import re
from dataclasses import dataclass, field
from typing import Any

from .pstring import PStr

Node = dict[str, Any]

MAX_ALTERNATIVES = 8   # different possible values per expression
MAX_LIST_ITEMS = 64

UNKNOWN = PStr.unknown()

_NULL_CODES = ("NULL", "0", "nullptr", "None", "null", "nil")


def _is_null_node(node: Node | None) -> bool:
    if not node:
        return False
    if node.get("k") == "call" and node.get("name") == "<operator>.cast":
        args = [a for a in node.get("args", []) if a.get("i", 0) >= 1]
        return bool(args) and _is_null_node(max(args, key=lambda a: a["i"])["v"])
    return node.get("k") == "lit" and node.get("code", "").strip() in _NULL_CODES

# --------------------------------------------------------------------------
# Literal decoding per language
# --------------------------------------------------------------------------

_C_ESCAPES = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v",
              "\\": "\\", "'": "'", '"': '"', "?": "?", "e": "\x1b", "0": "\0", "s": " "}

_STRING_START = re.compile(r"""^(?P<prefix>[A-Za-z0-9@$]*)(?P<quote>\"\"\"|'''|"|'|`)""", re.S)


def _unescape_c_like(body: str, drop_unknown_backslash: bool = False) -> str:
    """Process C/Java/JS/PHP/Go style escapes. Unknown escapes keep the backslash
    (C, Java, Go, PHP behaviour) or drop it (JavaScript behaviour)."""
    out: list[str] = []
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        e = body[i + 1]
        if e in "xX" and i + 2 < n and re.match(r"[0-9a-fA-F]", body[i + 2]):
            m = re.match(r"[0-9a-fA-F]{1,2}", body[i + 2:])
            out.append(chr(int(m.group(0), 16)))
            i += 2 + len(m.group(0))
        elif e == "u" and i + 2 < n and body[i + 2] == "{":
            end = body.find("}", i + 3)
            try:
                out.append(chr(int(body[i + 3:end], 16)))
                i = end + 1
            except ValueError:
                out.append("\\u")
                i += 2
        elif e in "uU" and re.match(r"[0-9a-fA-F]{4}", body[i + 2:i + 6]):
            width = 8 if e == "U" and re.match(r"[0-9a-fA-F]{8}", body[i + 2:i + 10]) else 4
            out.append(chr(int(body[i + 2:i + 2 + width], 16)))
            i += 2 + width
        elif e in "01234567" and re.match(r"[0-7]{1,3}", body[i + 1:]):
            m = re.match(r"[0-7]{1,3}", body[i + 1:])
            out.append(chr(int(m.group(0), 8)))
            i += 1 + len(m.group(0))
        elif e in _C_ESCAPES:
            out.append(_C_ESCAPES[e])
            i += 2
        elif e == "\n":  # line continuation
            i += 2
        else:
            if not drop_unknown_backslash:
                out.append("\\")
            out.append(e)
            i += 2
    return "".join(out)


def _decode_python(code: str) -> str | None:
    try:
        val = ast.literal_eval(code)
    except Exception:
        return None
    if isinstance(val, bytes):
        return val.decode("latin-1")
    if isinstance(val, (str, int, float, bool)) or val is None:
        return str(val)
    return None


def _split_adjacent_c_literals(code: str) -> list[str] | None:
    """C/C++ concatenate adjacent literals: "a" "b" -> ab. Returns literal bodies."""
    bodies: list[str] = []
    rest = code.strip()
    while rest:
        m = re.match(r'(?:L|u8|u|U)?R"([^(\s]*)\((.*?)\)\1"', rest, re.S)  # raw string
        if m:
            bodies.append("\x00RAW" + m.group(2))
            rest = rest[m.end():].lstrip()
            continue
        m = re.match(r'(?:L|u8|u|U)?"((?:[^"\\]|\\.)*)"', rest, re.S)
        if not m:
            return None
        bodies.append(m.group(1))
        rest = rest[m.end():].lstrip()
    return bodies


def decode_literal(code: str, language: str) -> str:
    """Return the runtime value of a literal's source code (best effort)."""
    lang = (language or "").upper()
    if not code:
        return ""
    stripped = code.strip()
    m = _STRING_START.match(stripped)
    quoted = m is not None and len(stripped) >= 2 and stripped[-1] in "\"'`"
    if "PYTHON" in lang:
        if quoted:
            val = _decode_python(stripped)
            if val is not None:
                return val
        else:
            # f-string literal parts are exported without quotes by pysrc2cpg: keep whitespace
            val = _decode_python('"""' + code.replace('"""', '\\"\\"\\"') + ' """')
            return val[:-1] if val is not None else code
    if lang in ("C", "NEWC", "CPP", "C++") or lang.startswith("NEWC"):
        bodies = _split_adjacent_c_literals(stripped)
        if bodies is not None:
            return "".join(b[4:] if b.startswith("\x00RAW") else _unescape_c_like(b) for b in bodies)
        if stripped.startswith("'") and stripped.endswith("'") and len(stripped) >= 3:
            return _unescape_c_like(stripped[1:-1])
        return stripped  # numbers, NULL, macros...
    if not quoted:
        return stripped  # numbers, booleans, null, identifiers
    prefix, quote = m.group("prefix"), m.group("quote")
    body = stripped[m.end():]
    if body.endswith(quote):
        body = body[: -len(quote)]
    if quote == "`":  # Go raw string / JS template without expressions
        return body if "GO" in lang else _unescape_c_like(body, drop_unknown_backslash=True)
    if "CSHARP" in lang and "@" in prefix:  # C# verbatim string
        return body.replace('""', '"')
    if ("PHP" in lang or "RUBY" in lang) and quote == "'":
        return body.replace("\\\\", "\\").replace("\\'", "'")
    if quote in ('"""', "'''"):  # Java/Kotlin text blocks
        lines = body.split("\n")
        if lines and not lines[0].strip():
            lines = lines[1:]
        indent = min((len(line) - len(line.lstrip()) for line in lines if line.strip()), default=0)
        body = "\n".join(line[indent:] for line in lines)
    return _unescape_c_like(body, drop_unknown_backslash="JS" in lang)


# --------------------------------------------------------------------------
# Resolution of value trees
# --------------------------------------------------------------------------

def _limit(alts: list[PStr]) -> list[PStr]:
    seen: list[PStr] = []
    for a in alts:
        if a not in seen:
            seen.append(a)
        if len(seen) >= MAX_ALTERNATIVES:
            break
    return seen or [UNKNOWN]


def _concat(alt_lists: list[list[PStr]]) -> list[PStr]:
    out: list[PStr] = []
    for combo in itertools.islice(itertools.product(*alt_lists), MAX_ALTERNATIVES * 4):
        acc = PStr()
        for part in combo:
            acc = acc + part
        out.append(acc)
    return _limit(out)


_PRINTF = re.compile(r"%(?P<flags>[-+ #0]*)(?P<width>\*|\d+)?(?:\.(?P<prec>\*|\d+))?(?P<len>hh|h|ll|l|L|q|j|z|t|I64|I32|I)?(?P<conv>[diouxXeEfFgGaAcCsSpn%@])")
_PY_FORMAT = re.compile(r"\{\{|\}\}|\{(?P<field>[^{}!:]*)(?:![rsa])?(?::[^{}]*)?\}")
_DOTNET_FORMAT = re.compile(r"\{\{|\}\}|\{(?P<idx>\d+)(?:,[^{}:]*)?(?::[^{}]*)?\}")


@dataclass
class Resolver:
    """Evaluates value trees of one extractor output (one language)."""

    language: str
    stats: dict[str, int] = field(default_factory=dict)

    # ---- public API ---------------------------------------------------------
    def string(self, node: Node | None) -> list[PStr]:
        """All (partially known) string values the expression may have."""
        if not node:
            return [UNKNOWN]
        return _limit(self._string(node, 0))

    def string_list(self, node: Node | None) -> list[PStr] | None:
        """Elements of a list/array expression (argv), or None if not a list."""
        if not node:
            return None
        return self._list(node, 0)

    def literal_text(self, node: Node | None) -> str | None:
        """Known text of a node if it is (or resolves to exactly) one known string."""
        alts = self.string(node)
        if len(alts) == 1 and not alts[0].has_gap:
            return alts[0].text
        return None

    # ---- internals ------------------------------------------------------------
    def _lit(self, node: Node) -> PStr:
        return PStr.known(decode_literal(node.get("code", ""), self.language))

    def _string(self, node: Node, depth: int) -> list[PStr]:
        if depth > 40:
            return [UNKNOWN]
        kind = node.get("k")
        if kind == "lit":
            return [self._lit(node)]
        if kind in ("id", "field"):
            return self._variable(node, depth)
        if kind == "call":
            return self._call(node, depth)
        if kind == "block" and node.get("items"):  # value of a block = its last expression
            return self._string(node["items"][-1], depth + 1)
        return [UNKNOWN]

    def _args(self, node: Node) -> list[Node]:
        args = [a for a in node.get("args", []) if a.get("i", -1) >= 1]
        return [a["v"] for a in sorted(args, key=lambda a: a["i"])]

    def _arg(self, node: Node, index: int) -> Node | None:
        for a in node.get("args", []):
            if a.get("i") == index:
                return a.get("v")
        return None

    def _kwarg(self, node: Node, name: str) -> Node | None:
        for a in node.get("args", []):
            if a.get("n") == name:
                return a.get("v")
        return None

    def _variable(self, node: Node, depth: int) -> list[PStr]:
        ops = node.get("defs", []) + node.get("writers", [])
        local_ops = [o for o in ops if o.get("local", True)]
        if local_ops:
            return self._replay(sorted(local_ops, key=lambda o: (o.get("line") or 0, o.get("col") or 0)), depth)
        global_defs = [o for o in node.get("defs", []) if not o.get("local", True)]
        if global_defs:
            alts: list[PStr] = []
            for d in global_defs:
                if d.get("op", "").endswith("assignment"):
                    alts.extend(self._string(d["v"], depth + 1))
            return _limit(alts) if alts else [UNKNOWN]
        param = node.get("param")
        if param and param.get("callers"):
            alts = []
            for c in param["callers"]:
                alts.extend(self._string(c, depth + 1))
            return _limit(alts)
        return [UNKNOWN]

    def _replay(self, ops: list[Node], depth: int) -> list[PStr]:
        """Replay assignments/buffer writes in source order (flow-insensitive within branches)."""
        state: list[PStr] = [UNKNOWN]
        for op in ops:
            name = op.get("op") or op.get("fn") or ""
            if "v" in op:  # assignment
                val = self._string(op["v"], depth + 1)
                if name.endswith("assignment"):
                    state = val
                elif name.endswith(("assignmentPlus", "assignmentConcat")):
                    state = _concat([state, val])
                else:
                    state = [UNKNOWN]
                continue
            args = [a.get("v") for a in sorted(op.get("args", []), key=lambda a: a.get("i", 0))]
            low = name.lower()
            sized = low.endswith("_s") or low.startswith("stringc")  # strcpy_s(dst, size, src) etc.
            if re.search(r"cpy|copy", low):
                src = 2 if sized else 1
                state = self._string(args[src], depth + 1) if len(args) > src else [UNKNOWN]
            elif re.search(r"cat", low):
                src = 2 if sized else 1
                state = _concat([state, self._string(args[src], depth + 1)]) if len(args) > src else [UNKNOWN]
            elif "printf" in low:
                fmt_index = 2 if (sized or re.search(r"^(_?sn|_snw|sw|vsn)", name, re.I)) else 1
                if fmt_index < len(args):
                    state = self._printf(args[fmt_index], args[fmt_index + 1:], depth)
                else:
                    state = [UNKNOWN]
            else:
                state = [UNKNOWN]
        return _limit(state)

    def _printf(self, fmt_node: Node | None, arg_nodes: list[Node | None], depth: int) -> list[PStr]:
        fmt = self.literal_text(fmt_node)
        if fmt is None:
            return [UNKNOWN]
        out_alts: list[list[PStr]] = []
        pos, argi = 0, 0
        for m in _PRINTF.finditer(fmt):
            out_alts.append([PStr.known(fmt[pos:m.start()])])
            conv = m.group("conv")
            if conv == "%":
                out_alts.append([PStr.known("%")])
            else:
                for star in (m.group("width"), m.group("prec")):
                    if star == "*":
                        argi += 1
                node = arg_nodes[argi] if argi < len(arg_nodes) else None
                argi += 1
                if conv in "sS@" and node is not None:
                    out_alts.append(self._string(node, depth + 1))
                elif node is not None and node.get("k") == "lit":
                    out_alts.append([self._lit(node)])
                else:
                    out_alts.append([UNKNOWN])
            pos = m.end()
        out_alts.append([PStr.known(fmt[pos:])])
        return _concat(out_alts)

    def _template(self, template: Node | None, positional: list[Node], named: dict[str, Node], depth: int,
                  dotnet: bool = False) -> list[PStr]:
        fmt = self.literal_text(template)
        if fmt is None:
            return [UNKNOWN]
        rx = _DOTNET_FORMAT if dotnet else _PY_FORMAT
        out_alts: list[list[PStr]] = []
        pos, auto = 0, 0
        for m in rx.finditer(fmt):
            out_alts.append([PStr.known(fmt[pos:m.start()])])
            tok = m.group(0)
            if tok in ("{{", "}}"):
                out_alts.append([PStr.known(tok[0])])
            else:
                key = m.group("idx") if dotnet else m.group("field")
                node: Node | None = None
                if key is None or key == "":
                    node = positional[auto] if auto < len(positional) else None
                    auto += 1
                elif key.isdigit():
                    idx = int(key)
                    node = positional[idx] if idx < len(positional) else None
                else:
                    node = named.get(key)
                out_alts.append(self._string(node, depth + 1) if node else [UNKNOWN])
            pos = m.end()
        out_alts.append([PStr.known(fmt[pos:])])
        return _concat(out_alts)

    def _call(self, node: Node, depth: int) -> list[PStr]:
        name = node.get("name", "")
        full = node.get("fullName", "") or ""
        args = self._args(node)
        if name in ("<operator>.addition", "<operator>.concat", "<operator>.plus", "<operator>.stringConcat"):
            return _concat([self._string(a, depth + 1) for a in args])
        if name in ("<operator>.formatString", "encaps", "<operator>.encaps", "<operator>.interpolation"):
            return _concat([self._string(a, depth + 1) for a in args])
        if name in ("<operator>.formattedValue", "<operator>.paren", "<operator>.toString"):
            return self._string(args[0], depth + 1) if args else [UNKNOWN]
        if name == "<operator>.cast":  # (type) expr -> the expression is the last argument
            return self._string(args[-1], depth + 1) if args else [UNKNOWN]
        if name == "<operator>.conditional" and len(args) >= 3:
            return _limit(self._string(args[1], depth + 1) + self._string(args[2], depth + 1))
        if name == "<operator>.modulo" and args:  # Python "fmt" % args
            rhs = args[1] if len(args) > 1 else None
            items = self._list(rhs, depth + 1) if rhs else None
            nodes = items if items is not None else ([rhs] if rhs else [])
            if items is not None:
                return self._printf_values(args[0], items)
            return self._printf(args[0], nodes, depth)
        if name in ("format",) and "PYTHON" in self.language.upper():
            instance = self._arg(node, 0)
            named = {a["n"]: a["v"] for a in node.get("args", []) if a.get("n")}
            return self._template(instance, args, named, depth)
        if name in ("format", "formatted") and args and ("java" in full.lower() or "String" in node.get("code", "")):
            return self._printf(args[0], args[1:], depth)
        if name == "Format" and args:  # .NET string.Format
            return self._template(args[0], args[1:], {}, depth, dotnet=True)
        if name in ("sprintf", "Sprintf", "format") and args:  # PHP/Go/Ruby style
            return self._printf(args[0], args[1:], depth)
        if name in ("join", "Join", "implode"):
            return self._join(node, args, depth)
        if name in ("str", "String", "valueOf", "fsdecode", "fspath"):  # conversion functions: f(x)
            return self._string(args[0], depth + 1) if args else [UNKNOWN]
        if name in ("toString", "strip", "trim", "lower", "upper", "lstrip", "rstrip", "toLowerCase",
                    "toUpperCase", "ToLower", "ToUpper", "Trim", "decode", "encode"):  # methods: x.f()
            inner = self._arg(node, 0)
            return self._string(inner, depth + 1) if inner else [UNKNOWN]
        if name == "concat" and self._arg(node, 0) is not None:  # Java "a".concat(b)
            return _concat([self._string(self._arg(node, 0), depth + 1)] + [self._string(a, depth + 1) for a in args])
        return [UNKNOWN]

    def _printf_values(self, fmt_node: Node, values: list[PStr]) -> list[PStr]:
        fmt = self.literal_text(fmt_node)
        if fmt is None:
            return [UNKNOWN]
        parts: list[PStr] = []
        pos, argi = 0, 0
        for m in _PRINTF.finditer(fmt):
            parts.append(PStr.known(fmt[pos:m.start()]))
            if m.group("conv") == "%":
                parts.append(PStr.known("%"))
            else:
                parts.append(values[argi] if argi < len(values) else UNKNOWN)
                argi += 1
            pos = m.end()
        parts.append(PStr.known(fmt[pos:]))
        acc = PStr()
        for p in parts:
            acc = acc + p
        return [acc]

    def _join(self, node: Node, args: list[Node], depth: int) -> list[PStr]:
        lang = self.language.upper()
        name = node.get("name", "")
        if "PYTHON" in lang:  # sep.join(items)
            sep = self.literal_text(self._arg(node, 0))
            items = self._list(args[0], depth + 1) if args else None
        elif name == "implode" and len(args) >= 2:  # PHP implode(sep, items)
            sep = self.literal_text(args[0])
            items = self._list(args[1], depth + 1)
        elif name == "Join" and len(args) >= 2 and "GO" in lang:  # Go strings.Join(items, sep)
            sep = self.literal_text(args[1])
            items = self._list(args[0], depth + 1)
        elif args:  # Java String.join(sep, items...) / JS items.join(sep)
            if self._arg(node, 0) is not None and "JS" in lang:
                sep = self.literal_text(args[0]) if args else ","
                items = self._list(self._arg(node, 0), depth + 1)
            else:
                sep = self.literal_text(args[0])
                rest = args[1:]
                items = self._list(rest[0], depth + 1) if len(rest) == 1 else [self.string(r)[0] for r in rest]
        else:
            return [UNKNOWN]
        if sep is None or items is None:
            return [UNKNOWN]
        return [PStr.join(sep, items)]

    _LIST_OPS = ("<operator>.listLiteral", "<operator>.tupleLiteral", "<operator>.arrayInitializer",
                 "<operator>.array", "array", "<operator>.arrayLiteral", "asList", "of", "listOf", "arrayOf",
                 "mutableListOf", "List", "list", "tuple", "Array")

    def _list(self, node: Node | None, depth: int) -> list[PStr] | None:
        if not node or depth > 40:
            return None
        kind = node.get("k")
        if kind in ("id", "field"):
            ops = [o for o in node.get("defs", []) if o.get("op", "").endswith("assignment")]
            if ops:
                last = sorted(ops, key=lambda o: (o.get("local", True), o.get("line") or 0))[-1]
                return self._list(last.get("v"), depth + 1)
            param = node.get("param")
            if param and param.get("callers"):
                return self._list(param["callers"][0], depth + 1)
            return None
        if kind == "block":
            return self._block_list(node, depth)
        if kind != "call":
            return None
        name = node.get("name", "")
        if name in self._LIST_OPS:
            elems = self._args(node)
            out: list[PStr] = []
            for e in elems[:MAX_LIST_ITEMS]:
                if _is_null_node(e):
                    break  # argv terminator
                if e.get("k") == "call" and e.get("name") in ("<operator>.arrayInitializer",):
                    nested = self._list(e, depth + 1)
                    if nested is not None:
                        out.extend(nested)
                        continue
                out.append(self._string(e, depth + 1)[0])
            return out
        if name == "<operator>.alloc" or name == "<init>":
            for a in self._args(node):
                lst = self._list(a, depth + 1)
                if lst is not None:
                    return lst
            return None
        if name == "split":  # "a b c".split() / .split(" ")
            base = self._arg(node, 0)
            text = self.literal_text(base)
            if text is not None:
                sep = self.literal_text(self._args(node)[0]) if self._args(node) else None
                return [PStr.known(t) for t in (text.split(sep) if sep else text.split())]
        return None

    def _block_list(self, node: Node, depth: int) -> list[PStr] | None:
        """Array literals lowered into blocks: JS ``_tmp.push(x)`` / PHP ``$tmp[i] = x``."""
        out: list[PStr] = []
        for item in node.get("items", []):
            if item.get("k") != "call":
                continue
            name, code = item.get("name", ""), item.get("code", "")
            if name in ("", "push") and ".push(" in code:
                elem = self._arg(item, 1)
                if elem is not None:
                    out.append(self._string(elem, depth + 1)[0])
            elif name == "<operator>.assignment":
                target = self._arg(item, 1)
                if target and target.get("k") == "call" and target.get("name") == "<operator>.indexAccess":
                    out.append(self._string(self._arg(item, 2), depth + 1)[0] if self._arg(item, 2) else PStr.unknown())
        return out if out else None
