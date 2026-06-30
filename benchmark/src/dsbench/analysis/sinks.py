"""Multi-language taint knowledge base: SOURCES, SINKS, SANITIZERS, REMEDIATION.

Deliberately small, explicit and auditable — a reviewer can read exactly what is
treated as dangerous (sink), as untrusted (source) and as neutralising
(sanitizer), per language family. The tables list names purely as *strings to
match* against parsed code; nothing here is ever imported or executed.

A "kind" groups sinks by vulnerability class so severity and remediation can be
specific. Severity is the inherent danger of the class *before* reachability /
sanitization is taken into account; the engine adjusts it from graph evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Severity


@dataclass(frozen=True)
class SinkSpec:
    kind: str
    cwe: str
    severity: Severity


# Vulnerability classes → (CWE, baseline severity, remediation).
KINDS: dict[str, tuple[str, Severity, str]] = {
    "command-injection": (
        "CWE-78", Severity.CRITICAL,
        "Avoid the shell: pass an argument list (shell=False / exec-array) and "
        "validate/allowlist the value; if a shell is unavoidable, quote each "
        "argument (shlex.quote / equivalent).",
    ),
    "code-injection": (
        "CWE-95", Severity.CRITICAL,
        "Never eval/exec untrusted input. Parse data with a safe parser "
        "(ast.literal_eval, JSON) or dispatch on an explicit allowlist.",
    ),
    "deserialization": (
        "CWE-502", Severity.HIGH,
        "Do not deserialize untrusted data with pickle/yaml.load/native "
        "deserializers. Use JSON or a schema-validated, type-safe format.",
    ),
    "sql-injection": (
        "CWE-89", Severity.HIGH,
        "Use parameterized queries (placeholders + a params list). Never build "
        "SQL by string concatenation or interpolation.",
    ),
    "path-traversal": (
        "CWE-22", Severity.HIGH,
        "Resolve the path and confirm it stays within an allowed base directory "
        "(realpath + prefix check); reject '..' and absolute paths.",
    ),
    "ssrf": (
        "CWE-918", Severity.HIGH,
        "Validate the URL against an allowlist of hosts/schemes; block private, "
        "loopback and link-local ranges; disable redirects to internal targets.",
    ),
    "xss": (
        "CWE-79", Severity.HIGH,
        "Never write untrusted data into HTML/DOM unescaped. Use textContent / "
        "auto-escaping templates; sanitize HTML with a vetted library.",
    ),
    "xxe": (
        "CWE-611", Severity.HIGH,
        "Disable external entity and DTD processing in the XML parser.",
    ),
    "ldap-injection": (
        "CWE-90", Severity.MEDIUM,
        "Escape LDAP special characters / use a parameterized filter API.",
    ),
    "template-injection": (
        "CWE-94", Severity.HIGH,
        "Never render untrusted input as a template. Pass it as data to a "
        "sandboxed, auto-escaping engine.",
    ),
}


def spec(kind: str) -> SinkSpec:
    cwe, sev, _ = KINDS[kind]
    return SinkSpec(kind=kind, cwe=cwe, severity=sev)


def remediation(kind: str) -> str:
    return KINDS.get(kind, ("", Severity.MEDIUM, ""))[2]


# --------------------------------------------------------------------------- #
# Per-language-family tables. The key is a "family" (python, js, java, go,
# ruby, php, c, csharp). The treesitter scanner maps file extensions to a
# family; the Python AST engine uses the "python" family directly.
# --------------------------------------------------------------------------- #

# Calls whose return value / read introduces untrusted data.
SOURCES: dict[str, set[str]] = {
    "python": {
        "input", "os.getenv", "os.environ", "request.args.get", "request.form.get",
        "request.values.get", "request.get_json", "request.args",
        "request.form", "request.values", "request.data", "request.cookies",
        "request.json", "request.files", "request.headers", "request.GET", "request.POST",
        "self.rfile.read", "parse_qs", "sys.argv", "sys.stdin", "raw_input", "flask.request",
    },
    "js": {
        "req.query", "req.body", "req.params", "req.cookies", "req.headers",
        "process.argv", "process.env", "url.parse", "location.search",
        "location.hash", "document.location", "document.URL", "document.referrer",
        "window.name", "localStorage", "sessionStorage", "URLSearchParams",
    },
    "java": {
        "request.getParameter", "request.getParameterValues",
        "request.getHeader", "request.getQueryString", "request.getCookies",
        "getParameter", "getHeader", "System.getenv", "args",
    },
    "go": {
        "r.URL.Query", "r.FormValue", "r.PostFormValue", "r.Header.Get",
        "os.Args", "os.Getenv", "r.Body",
    },
    "ruby": {"params", "request.params", "ENV", "ARGV", "gets", "cookies"},
    "php": {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "file_get_contents"},
    "csharp": {
        "Request.Query", "Request.Form", "Request.QueryString", "Request.Params",
        "Request.Headers", "Console.ReadLine", "Environment.GetEnvironmentVariable",
    },
    "c": {"getenv", "scanf", "gets", "fgets", "read", "recv"},
    "rust": {"web::Query", "web::Form", "web::Path", "web::Json", "std::env::var", "std::env::args"},
}

# Substrings in an attribute/identifier path that mark a value as request-derived.
SOURCE_ATTRS: dict[str, tuple[str, ...]] = {
    "python": ("request.args", "request.form", "request.values", "query_params", "request.json"),
    "js": ("req.query", "req.body", "req.params", "req.cookies", "req.headers"),
    "java": ("getParameter", "getHeader"),
    "go": ("URL.Query", "FormValue", "Header.Get"),
    "ruby": ("params",),
    "php": ("$_GET", "$_POST", "$_REQUEST"),
    "csharp": ("Request.",),
    "c": (),
}

# Dangerous calls grouped by kind. Matched against the full dotted callee and
# its last segment (so both ``os.system`` and a bare ``system`` match).
SINKS: dict[str, dict[str, str]] = {
    "python": {
        "os.system": "command-injection", "os.popen": "command-injection",
        "subprocess.call": "command-injection", "subprocess.run": "command-injection",
        "subprocess.Popen": "command-injection", "subprocess.check_output": "command-injection",
        "subprocess.check_call": "command-injection", "commands.getoutput": "command-injection",
        "subprocess.getoutput": "command-injection", "subprocess.getstatusoutput": "command-injection",
        "asyncio.create_subprocess_shell": "command-injection",
        "asyncio.create_subprocess_exec": "command-injection",
        "eval": "code-injection", "exec": "code-injection", "compile": "code-injection",
        "importlib.import_module": "code-injection", "__import__": "code-injection",
        "pickle.loads": "deserialization", "pickle.load": "deserialization",
        "cPickle.loads": "deserialization", "cPickle.load": "deserialization",
        "yaml.load": "deserialization", "yaml.unsafe_load": "deserialization",
        "marshal.loads": "deserialization", "marshal.load": "deserialization",
        "shelve.open": "deserialization",
        "cursor.execute": "sql-injection", "execute": "sql-injection",
        "executemany": "sql-injection", "raw": "sql-injection",
        "open": "path-traversal", "send_file": "path-traversal", "io.open": "path-traversal",
        "shutil.copy": "path-traversal", "shutil.copyfile": "path-traversal",
        "shutil.move": "path-traversal", "os.remove": "path-traversal", "os.unlink": "path-traversal",
        "tarfile.open": "path-traversal", "zipfile.ZipFile": "path-traversal",
        "read_text": "path-traversal", "write_text": "path-traversal",
        "urlopen": "ssrf", "requests.get": "ssrf", "requests.post": "ssrf",
        "requests.put": "ssrf", "requests.delete": "ssrf", "requests.patch": "ssrf",
        "httpx.get": "ssrf", "httpx.post": "ssrf",
        "aiohttp.ClientSession.get": "ssrf", "aiohttp.ClientSession.post": "ssrf",
        "render_template_string": "template-injection",
        "etree.parse": "xxe", "etree.fromstring": "xxe",
    },
    "js": {
        "child_process.exec": "command-injection", "child_process.execSync": "command-injection",
        "exec": "command-injection", "execSync": "command-injection",
        "child_process.spawn": "command-injection", "child_process.spawnSync": "command-injection",
        "child_process.execFile": "command-injection", "child_process.fork": "command-injection",
        "eval": "code-injection", "Function": "code-injection",
        "vm.runInContext": "code-injection", "vm.runInNewContext": "code-injection",
        "vm.runInThisContext": "code-injection",
        "query": "sql-injection", "raw": "sql-injection",
        "knex.raw": "sql-injection", "sequelize.query": "sql-injection",
        "fs.readFile": "path-traversal", "fs.readFileSync": "path-traversal",
        "fs.writeFile": "path-traversal", "fs.writeFileSync": "path-traversal",
        "fs.unlink": "path-traversal",
        "fs.createReadStream": "path-traversal", "res.sendFile": "path-traversal",
        "innerHTML": "xss", "outerHTML": "xss", "insertAdjacentHTML": "xss",
        "document.write": "xss", "dangerouslySetInnerHTML": "xss",
        "http.get": "ssrf", "http.request": "ssrf", "axios.get": "ssrf",
        "axios.post": "ssrf", "fetch": "ssrf", "got": "ssrf",
    },
    "java": {
        "Runtime.exec": "command-injection", "getRuntime.exec": "command-injection",
        "exec": "command-injection", "ProcessBuilder": "command-injection",
        "createStatement": "sql-injection", "executeQuery": "sql-injection",
        "executeUpdate": "sql-injection", "execute": "sql-injection",
        "createNativeQuery": "sql-injection",
        "ObjectInputStream": "deserialization", "readObject": "deserialization",
        "XMLDecoder": "deserialization", "XStream.fromXML": "deserialization",
        "ScriptEngine.eval": "code-injection", "GroovyShell.evaluate": "code-injection",
        "new File": "path-traversal", "Files.newInputStream": "path-traversal",
        "Files.readAllBytes": "path-traversal", "Files.write": "path-traversal",
        "DocumentBuilderFactory": "xxe", "SAXParserFactory": "xxe",
        "openConnection": "ssrf", "HttpURLConnection": "ssrf",
    },
    "go": {
        "exec.Command": "command-injection", "exec.CommandContext": "command-injection",
        "os/exec.Command": "command-injection", "syscall.Exec": "command-injection",
        "os.StartProcess": "command-injection",
        "db.Query": "sql-injection", "db.Exec": "sql-injection",
        "db.QueryRow": "sql-injection", "tx.Query": "sql-injection",
        "tx.Exec": "sql-injection", "stmt.Query": "sql-injection",
        "os.Open": "path-traversal", "os.OpenFile": "path-traversal",
        "os.Create": "path-traversal", "os.WriteFile": "path-traversal",
        "ioutil.ReadFile": "path-traversal", "ioutil.WriteFile": "path-traversal",
        "os.ReadFile": "path-traversal", "http.ServeFile": "path-traversal",
        "http.Get": "ssrf", "http.Post": "ssrf",
        "template.HTML": "xss",
    },
    "ruby": {
        "system": "command-injection", "exec": "command-injection", "spawn": "command-injection",
        "Open3.capture2": "command-injection", "Open3.capture3": "command-injection",
        "IO.popen": "command-injection", "Kernel.system": "command-injection",
        "eval": "code-injection", "instance_eval": "code-injection",
        "class_eval": "code-injection", "module_eval": "code-injection",
        "Marshal.load": "deserialization", "YAML.load": "deserialization",
        "execute": "sql-injection", "find_by_sql": "sql-injection", "exec_query": "sql-injection",
        "File.open": "path-traversal", "File.read": "path-traversal", "File.write": "path-traversal",
        "send_file": "path-traversal",
        "Net::HTTP.get": "ssrf", "open": "ssrf",
    },
    "php": {
        "system": "command-injection", "exec": "command-injection",
        "shell_exec": "command-injection", "passthru": "command-injection",
        "popen": "command-injection", "proc_open": "command-injection",
        "pcntl_exec": "command-injection",
        "eval": "code-injection", "assert": "code-injection",
        "create_function": "code-injection", "call_user_func": "code-injection",
        "call_user_func_array": "code-injection", "preg_replace": "code-injection",
        "unserialize": "deserialization",
        "mysqli_query": "sql-injection", "mysql_query": "sql-injection",
        "pg_query": "sql-injection", "query": "sql-injection",
        "fopen": "path-traversal", "file_get_contents": "path-traversal",
        "include": "path-traversal", "require": "path-traversal",
        "echo": "xss", "print": "xss",
    },
    "csharp": {
        "Process.Start": "command-injection", "ProcessStartInfo": "command-injection",
        "SqlCommand": "sql-injection", "ExecuteReader": "sql-injection",
        "ExecuteNonQuery": "sql-injection", "ExecuteScalar": "sql-injection",
        "BinaryFormatter": "deserialization", "Deserialize": "deserialization",
        "SoapFormatter": "deserialization", "LosFormatter": "deserialization",
        "Assembly.Load": "code-injection",
        "File.Open": "path-traversal", "File.ReadAllText": "path-traversal",
        "XmlDocument": "xxe",
        "WebClient": "ssrf", "HttpClient": "ssrf",
    },
    # Rust callees are normalized "::"→"." by the tree-sitter scanner, so keys
    # are dotted; common qualified prefixes are listed too.
    "rust": {
        "Command.new": "command-injection", "process.Command.new": "command-injection",
        "std.process.Command.new": "command-injection",
        "sqlx.query": "sql-injection", "diesel.sql_query": "sql-injection",
        "fs.read": "path-traversal", "fs.read_to_string": "path-traversal",
        "fs.write": "path-traversal", "std.fs.read_to_string": "path-traversal",
        "File.open": "path-traversal", "File.create": "path-traversal",
        "reqwest.get": "ssrf", "reqwest.blocking.get": "ssrf",
    },
    "c": {
        "system": "command-injection", "popen": "command-injection",
        "execve": "command-injection", "execl": "command-injection",
        "strcpy": "code-injection", "sprintf": "code-injection",
        "fopen": "path-traversal", "open": "path-traversal",
    },
}

# Calls that neutralise taint; data through one of these is considered clean.
SANITIZERS: dict[str, set[str]] = {
    "python": {
        "shlex.quote", "shlex.split", "pipes.quote", "html.escape", "escape", "markupsafe.escape",
        "os.path.realpath", "os.path.abspath", "os.path.basename", "os.path.normpath",
        "secure_filename", "int", "float", "bool", "quote", "urllib.parse.quote", "re.escape",
        "parameterize", "sanitize", "validate", "is_safe_url", "allowlist",
        "yaml.safe_load", "ast.literal_eval",
    },
    "js": {
        "encodeURIComponent", "encodeURI", "escape", "DOMPurify.sanitize",
        "sanitizeHtml", "validator.escape", "parseInt", "parseFloat",
        "path.basename", "path.normalize", "shellEscape",
    },
    "java": {
        "ESAPI.encoder", "encodeForHTML", "StringEscapeUtils.escapeHtml4",
        "Integer.parseInt", "getCanonicalPath", "Pattern.quote",
    },
    "go": {
        "html.EscapeString", "template.HTMLEscapeString", "url.QueryEscape",
        "filepath.Clean", "filepath.Base", "strconv.Atoi",
    },
    "ruby": {
        "Shellwords.escape", "CGI.escape", "CGI.escapeHTML", "ERB::Util.html_escape",
        "File.basename", "Integer", "sanitize",
    },
    "php": {
        "escapeshellarg", "escapeshellcmd", "htmlspecialchars", "htmlentities",
        "intval", "basename", "realpath", "mysqli_real_escape_string",
        "filter_var",
    },
    "csharp": {
        "HttpUtility.HtmlEncode", "Uri.EscapeDataString", "Path.GetFileName",
        "int.Parse", "Regex.Escape",
    },
    "c": {"snprintf", "strncpy", "realpath"},
    "rust": {"parse", "shell_escape", "PathBuf::from"},
}


# Map a source-file extension to a knowledge-base family.
EXT_TO_FAMILY: dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "js", ".tsx": "js", ".vue": "js", ".svelte": "js",
    ".java": "java", ".kt": "java", ".kts": "java", ".scala": "java", ".groovy": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c", ".cxx": "c", ".hpp": "c",
}


def family_for_ext(ext: str) -> str | None:
    return EXT_TO_FAMILY.get(ext.lower())
