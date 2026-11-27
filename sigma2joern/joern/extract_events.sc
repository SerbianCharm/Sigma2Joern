// sigma2joern – Joern extractor (static, generic, no code generation from rules)
//
// Exports every call that may start a process together with "value trees" that describe
// how its arguments are built: literals, reaching assignments of variables (incl. C buffer
// writes like strcpy/sprintf), arguments at the call sites of parameters, string
// concatenation, f-strings/template literals, lists/arrays, ...
// sigma2joern (Python) turns this into synthetic process events and evaluates Sigma rules.
//
// Usage:
//   joern --script extract_events.sc --param cpgFile=cpg.bin   --param outFile=events.json
//   joern --script extract_events.sc --param inputPath=./src   --param outFile=events.json
// Optional: --param names=<regex> --param maxDepth=8 --param maxNodes=400

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import scala.collection.mutable

// Keep in sync with sigma2joern/sinks.py:candidate_name_regex() (checked by the unit tests).
val DefaultSinkNames =
  """((?:(std::)?(_w?system|system|_?w?popen|popen))|(?:<init>|command)|(?:Command)|(?:CommandContext)|(?:CreateProcessAsUser[AW]?)|(?:CreateProcessWithLogonW)|(?:CreateProcessWithTokenW)|(?:CreateProcess[AW]?)|(?:Exec)|(?:Popen|check_call|check_output|getoutput|getstatusoutput)|(?:ShellExecute[AW]?)|(?:Start)|(?:WinExec)|(?:_?w?spawnl[pe]?)|(?:_?w?spawnv(p|e|pe)?)|(?:_w?execl[pe]?)|(?:_w?execv(p|e|pe)?)|(?:create_subprocess_exec)|(?:create_subprocess_shell)|(?:exec)|(?:execFile|execFileSync)|(?:execl[p]?e?)|(?:execl[pe]?)|(?:execv(p|e|pe)?)|(?:execv[p]?e?)|(?:exec|execSync)|(?:exec|system|passthru|shell_exec|popen|proc_open|<operator>\.shellExec)|(?:pcntl_exec)|(?:posix_spawnp?)|(?:run|call|check_call|check_output|Popen|getoutput|getstatusoutput)|(?:spawn)|(?:spawnl[p]?e?)|(?:spawnv[p]?e?)|(?:spawn|spawnSync)|(?:startfile)|(?:system|exec|spawn|capture2e?|capture3|popen[23]e?)|(?:system|popen))"""

// Very common method names are only exported when the call mentions a process API.
val GenericNames = Set("<init>", "command", "Command", "CommandContext", "Start", "run", "call", "spawn",
  "spawnSync", "Exec", "exec", "execSync")
val ProcessContext = """(?is).*(process|subprocess|child_process|childprocess|runtime|os/exec|exec\.|syscall|open3|kernel|pty|\bcp\.|\bos\.).*"""

val AssignOps = Set("<operator>.assignment", "<operator>.assignmentPlus", "<operator>.assignmentConcat")
val FieldOps  = Set("<operator>.fieldAccess", "<operator>.indirectFieldAccess")
val WriterRe  = """(?i)(.*(cpy|cat|copy)[aw]?(_s)?|.*printf[aw]?(_s)?|stringc[bc](copy|cat|printf)(ex)?[aw]?)"""

// ---------------------------------------------------------------------------------------------
// minimal JSON writer (pure ASCII output, so the file is always valid UTF-8)
// ---------------------------------------------------------------------------------------------
def esc(s: String): String = {
  val str = if (s == null) "" else s
  val sb  = new java.lang.StringBuilder(str.length + 16)
  sb.append('"')
  var i = 0
  while (i < str.length) {
    val c = str.charAt(i)
    if (c == '"') sb.append('\\').append('"')
    else if (c == '\\') sb.append('\\').append('\\')
    else if (c < 0x20 || c > 0x7e) {
      sb.append('\\').append('u').append(String.format("%04x", Integer.valueOf(c.toInt)))
    } else sb.append(c)
    i += 1
  }
  sb.append('"').toString
}
def obj(fields: (String, String)*): String = fields.map { case (k, v) => esc(k) + ":" + v }.mkString("{", ",", "}")
def arr(items: Iterable[String]): String  = items.mkString("[", ",", "]")
def num(o: Option[Int]): String           = o.map(_.toString).getOrElse("null")
def trunc(s: String, n: Int): String      = if (s == null) "" else if (s.length > n) s.substring(0, n) + "..." else s

// ---------------------------------------------------------------------------------------------
class Extractor(theCpg: Cpg, maxDepth: Int, maxNodes: Int, maxDefs: Int, maxCallers: Int) {
  private var budget = 0
  private val assignCache = mutable.HashMap.empty[Long, List[(String, Call)]]
  private val writerCache = mutable.HashMap.empty[Long, List[(String, Call)]]

  private def keyOf(e: Expression): Option[String] = e match {
    case i: Identifier                        => Some(i.name)
    case c: Call if FieldOps.contains(c.name) => c.argumentOption(2).map(_.code)
    case _                                    => None
  }
  private def targetKey(a: Call): Option[String] = a.argumentOption(1).flatMap(keyOf)

  private lazy val globalAssigns: Map[String, List[Call]] =
    theCpg.call.filter(c => AssignOps.contains(c.name)).l
      .flatMap(a => targetKey(a).map(k => (k, a)))
      .groupBy(_._1).map { case (k, v) => (k, v.map(_._2)) }

  private def methodAssigns(m: Method): List[(String, Call)] =
    assignCache.getOrElseUpdate(m.id(), m.ast.isCall.filter(c => AssignOps.contains(c.name)).l
      .flatMap(a => targetKey(a).map(k => (k, a))))

  private def methodWriters(m: Method): List[(String, Call)] =
    writerCache.getOrElseUpdate(m.id(), m.ast.isCall.filter(c => c.name.matches(WriterRe)).l
      .flatMap(w => w.argumentOption(1).map(a => (a.code.replaceAll("""^[&(\s]+|[)\s]+$""", ""), w))))

  private def pos(n: Expression): (Int, Int) =
    (n.lineNumber.getOrElse(Int.MaxValue), n.columnNumber.getOrElse(Int.MaxValue))
  private def before(a: Call, use: Expression): Boolean = {
    val (al, ac) = (a.lineNumber.getOrElse(-1), a.columnNumber.getOrElse(-1))
    val (ul, uc) = pos(use)
    al < ul || (al == ul && ac <= uc)
  }
  private def contains(root: Expression, n: Expression): Boolean = root.ast.exists(_.id() == n.id())

  private def opJson(a: Call, local: Boolean, depth: Int, vis: Set[Long]): String = {
    val src = a.argumentOption(2).map(s => dump(s, depth + 1, vis)).getOrElse(obj("k" -> esc("other"), "code" -> esc("")))
    obj("op" -> esc(a.name), "line" -> num(a.lineNumber), "col" -> num(a.columnNumber),
      "local" -> local.toString, "v" -> src)
  }

  private def writerJson(w: Call, depth: Int, vis: Set[Long]): String = {
    val args = w.argument.l.filter(_.argumentIndex >= 1).sortBy(_.argumentIndex).take(16).map { a =>
      obj("i" -> a.argumentIndex.toString, "v" -> (if (a.argumentIndex == 1) obj("k" -> esc("other"), "code" -> esc(trunc(a.code, 80))) else dump(a, depth + 1, vis)))
    }
    obj("fn" -> esc(w.name), "line" -> num(w.lineNumber), "col" -> num(w.columnNumber), "local" -> "true", "args" -> arr(args))
  }

  private def variable(node: Expression, key: String, kind: String, depth: Int, vis: Set[Long]): String = {
    val m = node.method
    val localDefs = methodAssigns(m).filter(_._1 == key).map(_._2)
      .filter(a => before(a, node) && !a.argumentOption(2).exists(src => contains(src, node)))
      .sortBy(a => (a.lineNumber.getOrElse(0), a.columnNumber.getOrElse(0))).takeRight(maxDefs)
    val writers = methodWriters(m).filter(_._1 == key).map(_._2).filter(w => before(w, node))
      .sortBy(w => (w.lineNumber.getOrElse(0), w.columnNumber.getOrElse(0))).takeRight(maxDefs)
    val param = node match {
      case i: Identifier => i.refOut.collectFirst { case p: MethodParameterIn => p }
      case _             => None
    }
    val globalDefs =
      if (localDefs.nonEmpty || writers.nonEmpty || param.nonEmpty) Nil
      else {
        val all      = globalAssigns.getOrElse(key, Nil).filterNot(a => a.method.id() == m.id())
        val sameFile = all.filter(_.method.filename == m.filename)
        (if (sameFile.nonEmpty || kind == "id") sameFile else all).take(maxDefs)
      }
    val paramJson = param match {
      case Some(p) if localDefs.isEmpty && writers.isEmpty =>
        val callers = Iterator.single(p.method).callIn.take(maxCallers).l
          .flatMap(c => c.argumentOption(p.index)).map(a => dump(a, depth + 1, vis))
        obj("index" -> p.index.toString, "method" -> esc(p.method.fullName), "callers" -> arr(callers))
      case _ => "null"
    }
    obj("k" -> esc(kind), "name" -> esc(key), "code" -> esc(trunc(node.code, 120)),
      "defs" -> arr(localDefs.map(a => opJson(a, local = true, depth, vis)) ++ globalDefs.map(a => opJson(a, local = false, depth, vis))),
      "writers" -> arr(writers.map(w => writerJson(w, depth, vis))),
      "param" -> paramJson)
  }

  def dump(e: Expression, depth: Int, visiting: Set[Long]): String = {
    budget += 1
    if (depth > maxDepth || budget > maxNodes || visiting.contains(e.id())) {
      obj("k" -> esc("cut"), "code" -> esc(trunc(e.code, 120)))
    } else {
      val vis = visiting + e.id()
      e match {
        case l: Literal    => obj("k" -> esc("lit"), "code" -> esc(trunc(l.code, 4000)))
        case i: Identifier => variable(i, i.name, "id", depth, vis)
        case c: Call if FieldOps.contains(c.name) =>
          variable(c, c.argumentOption(2).map(_.code).getOrElse(c.code), "field", depth, vis)
        case b: Block => // e.g. JS array literals: { _tmp = __ecma.Array.factory(); _tmp.push(x); ...; _tmp }
          val items = b.astChildren.l.collect { case x: Expression => x }.sortBy(_.order).take(64)
            .map(x => dump(x, depth + 1, vis))
          obj("k" -> esc("block"), "code" -> esc(trunc(b.code, 300)), "items" -> arr(items))
        case c: Call =>
          val args = c.argument.l.sortBy(_.argumentIndex).take(64).map { a =>
            obj("i" -> a.argumentIndex.toString, "n" -> a.argumentName.map(esc).getOrElse("null"),
              "v" -> dump(a, depth + 1, vis))
          }
          obj("k" -> esc("call"), "name" -> esc(c.name), "fullName" -> esc(c.methodFullName),
            "code" -> esc(trunc(c.code, 300)), "args" -> arr(args))
        case other => obj("k" -> esc("other"), "label" -> esc(other.label), "code" -> esc(trunc(other.code, 200)))
      }
    }
  }

  def callJson(c: Call): String = {
    budget = 0
    val args = c.argument.l.sortBy(_.argumentIndex).take(32).map { a =>
      obj("i" -> a.argumentIndex.toString, "n" -> a.argumentName.map(esc).getOrElse("null"), "v" -> dump(a, 0, Set.empty))
    }
    obj("id" -> c.id().toString, "name" -> esc(c.name), "fullName" -> esc(c.methodFullName),
      "code" -> esc(trunc(c.code, 500)), "file" -> esc(c.location.filename), "line" -> num(c.lineNumber),
      "method" -> esc(c.method.fullName), "receiver" -> esc(c.receiver.code.headOption.getOrElse("")),
      "args" -> arr(args))
  }
}

@main def exec(cpgFile: String = "", inputPath: String = "", outFile: String = "joern_events.json",
               names: String = "", maxDepth: Int = 8, maxNodes: Int = 400, maxDefs: Int = 4,
               maxCallers: Int = 4): Unit = {
  if (cpgFile.nonEmpty) importCpg(cpgFile)
  else if (inputPath.nonEmpty) importCode(inputPath)
  else throw new IllegalArgumentException("pass --param cpgFile=<cpg.bin> or --param inputPath=<source dir>")

  val theCpg    = cpg
  val language  = theCpg.metaData.language.headOption.getOrElse("")
  val nameRe    = if (names.nonEmpty) names else DefaultSinkNames
  val extractor = new Extractor(theCpg, maxDepth, maxNodes, maxDefs, maxCallers)
  val candidates = theCpg.call.name(nameRe).filter { c =>
    !GenericNames.contains(c.name) || {
      val recv = c.receiver.code.headOption.getOrElse("")
      recv.isEmpty || recv == c.name || (c.methodFullName + " " + c.code + " " + recv).matches(ProcessContext)
    }
  }.l
  var failed = 0
  val calls = candidates.flatMap { c =>
    scala.util.Try(extractor.callJson(c)) match {
      case scala.util.Success(js) => Some(js)
      case scala.util.Failure(err) =>
        failed += 1
        System.err.println(s"sigma2joern: skipped call ${c.code.take(80)}: ${err.getMessage}")
        None
    }
  }
  val json  = obj("tool" -> esc("sigma2joern-extractor"), "version" -> "1", "language" -> esc(language),
    "calls" -> arr(calls))
  Files.writeString(Paths.get(outFile), json, StandardCharsets.UTF_8)
  System.err.println(s"sigma2joern: exported ${calls.size} candidate call(s) ($language) to $outFile" +
    (if (failed > 0) s", $failed skipped" else ""))
}
