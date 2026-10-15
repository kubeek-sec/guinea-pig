#!/usr/bin/env python3
"""Generate the uniform per-theme ground-truth catalogs from the fixtures.

Single source of truth for the benchmark. Writes one ``benchmark/ground-truth/<theme>.json``
per fixture family, all sharing the same schema:

    benchmark/ground-truth/secrets.json    secrets/ fixtures + per-rule secret_catalogue + look-alikes
    benchmark/ground-truth/projects.json   projects/<lang>/app{,-patched} — authored in dataset/<lang>.json
    benchmark/ground-truth/pipeline.json   SCA manifests + CI/CD configs (+ the bumpy pyyaml project)
    benchmark/ground-truth/skills.json     malicious / benign Agent-skill fixtures (labels in src/skills_labels.json)

Common envelope::

    { schema_version, theme, report, summary, positives[], negatives[] [, secret_catalogue] [, apps] }

`positives` are expected to be detected; `negatives` are expected to stay clean.
The project weaknesses are authored in dataset/<lang>.json with *anchors* (a unique
substring of the line) that this script resolves to line numbers, so editing the
applications never silently desynchronises the ground truth: an anchor that no
longer matches exactly one line aborts the build. Re-run after any change::

    python3 benchmark/src/build_report.py
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

SRC = Path(__file__).resolve().parent
REPO = SRC.parents[1]                 # benchmark/src -> benchmark -> repo root
CWE_RE = re.compile(r"CWE-(\d+)")
SCHEMA_VERSION = "6.0"

# language (folder) -> scanner type(s) able to detect it
LANG_SCANNER = {
    "java": "SAST", "c": "SAST", "cpp": "SAST", "csharp": "SAST",
    "python": "SAST", "javascript": "SAST",
    "terraform": "IAC", "ansible": "IAC", "kubernetes": "IAC",
    "github": "PIPELINE", "gitlab": "PIPELINE",
    "env": "SECRET", "ini": "SECRET", "conf": "SECRET", "pem": "SECRET",
}
# CWEs that a SECRET scanner also catches even when they appear in source code
SECRET_ALSO = {"CWE-798", "CWE-321", "CWE-259", "CWE-256"}

CWE_INFO = {
    "CWE-22":   ("Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)", "High"),
    "CWE-78":   ("Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)", "Critical"),
    "CWE-79":   ("Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)", "High"),
    "CWE-89":   ("Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)", "Critical"),
    "CWE-90":   ("Improper Neutralization of Special Elements used in an LDAP Query (LDAP Injection)", "High"),
    "CWE-94":   ("Improper Control of Generation of Code (Code Injection)", "Critical"),
    "CWE-120":  ("Buffer Copy without Checking Size of Input (Classic Buffer Overflow)", "High"),
    "CWE-121":  ("Stack-based Buffer Overflow", "High"),
    "CWE-134":  ("Use of Externally-Controlled Format String", "High"),
    "CWE-190":  ("Integer Overflow or Wraparound", "Medium"),
    "CWE-200":  ("Exposure of Sensitive Information to an Unauthorized Actor", "Medium"),
    "CWE-209":  ("Generation of Error Message Containing Sensitive Information", "Low"),
    "CWE-242":  ("Use of Inherently Dangerous Function", "High"),
    "CWE-250":  ("Execution with Unnecessary Privileges", "Medium"),
    "CWE-256":  ("Plaintext Storage of a Password", "Medium"),
    "CWE-284":  ("Improper Access Control", "High"),
    "CWE-295":  ("Improper Certificate Validation", "High"),
    "CWE-311":  ("Missing Encryption of Sensitive Data", "High"),
    "CWE-319":  ("Cleartext Transmission of Sensitive Information", "High"),
    "CWE-321":  ("Use of Hard-coded Cryptographic Key", "High"),
    "CWE-327":  ("Use of a Broken or Risky Cryptographic Algorithm", "Medium"),
    "CWE-330":  ("Use of Insufficiently Random Values", "Medium"),
    "CWE-338":  ("Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)", "Medium"),
    "CWE-367":  ("Time-of-check Time-of-use (TOCTOU) Race Condition", "Medium"),
    "CWE-377":  ("Insecure Temporary File", "Medium"),
    "CWE-401":  ("Missing Release of Memory after Effective Lifetime (Memory Leak)", "Low"),
    "CWE-415":  ("Double Free", "High"),
    "CWE-416":  ("Use After Free", "High"),
    "CWE-476":  ("NULL Pointer Dereference", "Medium"),
    "CWE-494":  ("Download of Code Without Integrity Check", "High"),
    "CWE-502":  ("Deserialization of Untrusted Data", "Critical"),
    "CWE-601":  ("URL Redirection to Untrusted Site (Open Redirect)", "Medium"),
    "CWE-611":  ("Improper Restriction of XML External Entity Reference (XXE)", "High"),
    "CWE-614":  ("Sensitive Cookie in HTTPS Session Without 'Secure' Attribute", "Low"),
    "CWE-653":  ("Improper Isolation or Compartmentalization", "High"),
    "CWE-668":  ("Exposure of Resource to Wrong Sphere", "High"),
    "CWE-732":  ("Incorrect Permission Assignment for Critical Resource", "High"),
    "CWE-778":  ("Insufficient Logging", "Low"),
    "CWE-787":  ("Out-of-bounds Write", "High"),
    "CWE-798":  ("Use of Hard-coded Credentials", "High"),
    "CWE-829":  ("Inclusion of Functionality from Untrusted Control Sphere", "Medium"),
    "CWE-918":  ("Server-Side Request Forgery (SSRF)", "High"),
    "CWE-942":  ("Permissive Cross-domain Policy with Untrusted Domains", "Medium"),
    "CWE-1004": ("Sensitive Cookie Without 'HttpOnly' Flag", "Low"),
    "CWE-1321": ("Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)", "High"),
    "CWE-532":  ("Insertion of Sensitive Information into Log File", "Medium"),
    "CWE-1395": ("Dependency on Vulnerable Third-Party Component", "High"),
    "CWE-23":   ("Relative Path Traversal", "High"),
    "CWE-73":   ("External Control of File Name or Path", "High"),
    "CWE-77":   ("Improper Neutralization of Special Elements used in a Command (Command Injection)", "Critical"),
    "CWE-88":   ("Improper Neutralization of Argument Delimiters in a Command (Argument Injection)", "High"),
    "CWE-91":   ("XML Injection (aka Blind XPath Injection)", "High"),
    "CWE-95":   ("Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)", "Critical"),
    "CWE-113":  ("Improper Neutralization of CRLF Sequences in HTTP Headers (HTTP Response Splitting)", "Medium"),
    "CWE-117":  ("Improper Output Neutralization for Logs", "Low"),
    "CWE-122":  ("Heap-based Buffer Overflow", "High"),
    "CWE-125":  ("Out-of-bounds Read", "High"),
    "CWE-126":  ("Buffer Over-read", "High"),
    "CWE-129":  ("Improper Validation of Array Index", "High"),
    "CWE-131":  ("Incorrect Calculation of Buffer Size", "High"),
    "CWE-170":  ("Improper Null Termination", "Medium"),
    "CWE-191":  ("Integer Underflow (Wrap or Wraparound)", "Medium"),
    "CWE-193":  ("Off-by-one Error", "Medium"),
    "CWE-197":  ("Numeric Truncation Error", "Medium"),
    "CWE-208":  ("Observable Timing Discrepancy", "Low"),
    "CWE-259":  ("Use of Hard-coded Password", "High"),
    "CWE-269":  ("Improper Privilege Management", "High"),
    "CWE-276":  ("Incorrect Default Permissions", "Medium"),
    "CWE-285":  ("Improper Authorization", "High"),
    "CWE-287":  ("Improper Authentication", "Critical"),
    "CWE-290":  ("Authentication Bypass by Spoofing", "High"),
    "CWE-306":  ("Missing Authentication for Critical Function", "Critical"),
    "CWE-307":  ("Improper Restriction of Excessive Authentication Attempts", "Medium"),
    "CWE-312":  ("Cleartext Storage of Sensitive Information", "Medium"),
    "CWE-328":  ("Use of Weak Hash", "Medium"),
    "CWE-345":  ("Insufficient Verification of Data Authenticity", "High"),
    "CWE-347":  ("Improper Verification of Cryptographic Signature", "High"),
    "CWE-352":  ("Cross-Site Request Forgery (CSRF)", "Medium"),
    "CWE-362":  ("Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)", "Medium"),
    "CWE-369":  ("Divide By Zero", "Low"),
    "CWE-384":  ("Session Fixation", "Medium"),
    "CWE-400":  ("Uncontrolled Resource Consumption", "Medium"),
    "CWE-434":  ("Unrestricted Upload of File with Dangerous Type", "High"),
    "CWE-444":  ("Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)", "High"),
    "CWE-457":  ("Use of Uninitialized Variable", "Medium"),
    "CWE-470":  ("Use of Externally-Controlled Input to Select Classes or Code (Unsafe Reflection)", "High"),
    "CWE-489":  ("Active Debug Code", "Medium"),
    "CWE-521":  ("Weak Password Requirements", "Low"),
    "CWE-522":  ("Insufficiently Protected Credentials", "High"),
    "CWE-538":  ("Insertion of Sensitive Information into Externally-Accessible File or Directory", "Medium"),
    "CWE-552":  ("Files or Directories Accessible to External Parties", "Medium"),
    "CWE-562":  ("Return of Stack Variable Address", "High"),
    "CWE-565":  ("Reliance on Cookies without Validation and Integrity Checking", "Medium"),
    "CWE-590":  ("Free of Memory not on the Heap", "High"),
    "CWE-613":  ("Insufficient Session Expiration", "Medium"),
    "CWE-639":  ("Authorization Bypass Through User-Controlled Key (IDOR)", "High"),
    "CWE-640":  ("Weak Password Recovery Mechanism for Forgotten Password", "High"),
    "CWE-643":  ("Improper Neutralization of Data within XPath Expressions (XPath Injection)", "High"),
    "CWE-676":  ("Use of Potentially Dangerous Function", "Medium"),
    "CWE-681":  ("Incorrect Conversion between Numeric Types", "Medium"),
    "CWE-693":  ("Protection Mechanism Failure", "Medium"),
    "CWE-704":  ("Incorrect Type Conversion or Cast", "Medium"),
    "CWE-759":  ("Use of a One-Way Hash without a Salt", "Medium"),
    "CWE-770":  ("Allocation of Resources Without Limits or Throttling", "Medium"),
    "CWE-776":  ("Improper Restriction of Recursive Entity References in DTDs (XML Entity Expansion)", "Medium"),
    "CWE-807":  ("Reliance on Untrusted Inputs in a Security Decision", "High"),
    "CWE-843":  ("Access of Resource Using Incompatible Type (Type Confusion)", "High"),
    "CWE-862":  ("Missing Authorization", "High"),
    "CWE-863":  ("Incorrect Authorization", "High"),
    "CWE-915":  ("Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment)", "High"),
    "CWE-916":  ("Use of Password Hash With Insufficient Computational Effort", "Medium"),
    "CWE-917":  ("Improper Neutralization of Special Elements used in an Expression Language Statement (EL Injection)", "Critical"),
    "CWE-926":  ("Improper Export of Android Application Components", "Medium"),
    "CWE-943":  ("Improper Neutralization of Special Elements in Data Query Logic (NoSQL Injection)", "High"),
    "CWE-1021": ("Improper Restriction of Rendered UI Layers or Frames (Clickjacking)", "Low"),
    "CWE-1104": ("Use of Unmaintained Third Party Components", "Medium"),
    "CWE-1236": ("Improper Neutralization of Formula Elements in a CSV File", "Medium"),
    "CWE-1333": ("Inefficient Regular Expression Complexity (ReDoS)", "Medium"),
    "CWE-1336": ("Improper Neutralization of Special Elements Used in a Template Engine (SSTI)", "Critical"),
}

# SCA manifests (whole files; not CWE-named). (path, ecosystem, description).
SCA_MANIFESTS = [
    ("pipeline/sca/python/Pipfile", "python", "Django 3.0.1 and other Python packages with known CVEs."),
    ("pipeline/sca/ruby/Gemfile", "ruby", "rails 6.1.4 / devise with known CVEs."),
    ("pipeline/sca/node/package.json", "node", "lodash, minimist, express, axios, node-serialize with known CVEs."),
    ("pipeline/sca/java/pom.xml", "java", "log4j-core 2.14.1 (Log4Shell), jackson-databind, spring-web, snakeyaml."),
    ("pipeline/sca/bumpy/pyproject.toml", "python", "pyyaml==3.13 — a dependency with known RCE-via-yaml.load CVEs (CVE-2017-18342 and related)."),
]

# Extra source-level (SAST) sinks living in pipeline whole-file projects.
# (path, language, cwe, description, snippet)
PIPELINE_SAST = [
    ("pipeline/sca/bumpy/app/config_loader.py", "python", "CWE-502",
     "Loads YAML with the unsafe default Loader (yaml.load without SafeLoader), allowing arbitrary code execution from untrusted input.",
     "yaml.load() with the default (unsafe) Loader"),
    ("pipeline/sca/bumpy/demo/run_fixtures.py", "python", "CWE-502",
     "Deserializes fixture YAML via the legacy yaml.load() API, which executes !!python/object tags.",
     "yaml.load(raw)"),
]

_counter: Counter[str] = Counter()


def new_id(family: str) -> str:
    _counter[family] += 1
    return f"GP-{family}-{_counter[family]:03d}"


def cwe_entry(cwe: str, name: str = "") -> list[dict]:
    return [{"id": cwe, "name": name or CWE_INFO.get(cwe, ("", ""))[0]}]


# --------------------------------------------------------------------------- #
# Header parsing (secret fixtures + look-alikes)
# --------------------------------------------------------------------------- #
def strip_comment(line: str) -> str:
    s = line.strip()
    for m in ("/*", "*/", "<!--", "-->", "//", "#", ";"):
        s = s.replace(m, "")
    return s.strip(" *\t")


def parse_header(path: Path) -> dict:
    name = description = sink = ""
    try:
        lines = [strip_comment(l) for l in path.read_text(encoding="utf-8", errors="replace").splitlines()[:8]]
    except OSError:
        lines = []
    for i, c in enumerate(lines):
        if CWE_RE.search(c) and ":" in c and not name:
            name = c.split(":", 1)[1].strip()
            for nxt in lines[i + 1:]:
                if nxt and "sink" not in nxt.lower() and not description:
                    description = nxt
                    break
        if "sink" in c.lower() and not sink:
            sink = c.split(":", 1)[1].strip() if ":" in c else c
    return {"name": name, "description": description, "sink": sink}


def _clean_snippet(s: str) -> str:
    return s.strip().strip("*>` \t").replace("`", "").rstrip(".")


def _fp_header(path: Path) -> dict:
    try:
        blob = "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[:16])
    except OSError:
        return {"resembles": "", "reason": ""}

    def grab(label: str) -> str:
        m = re.search(rf"{label}\s*[:]?\s*(.+)", blob, re.IGNORECASE)
        return _clean_snippet(m.group(1)) if m else ""

    resembles = grab("Resembles")
    reason = grab("Why benign")
    if not reason:
        m = re.search(r'"_false_positive_note"\s*:\s*"([^"]+)"', blob)
        if m:
            reason = m.group(1)
            if not resembles:
                rm = re.search(r"Resembles\s+(.+?)(?:\.|$)", reason, re.IGNORECASE)
                if rm:
                    resembles = _clean_snippet(rm.group(1))
    return {"resembles": resembles, "reason": reason}


# --------------------------------------------------------------------------- #
# Positives per family
# --------------------------------------------------------------------------- #
def pipeline_positives() -> list[dict]:
    out = []
    # SCA manifests (CWE-1395)
    name_1395, sev_1395 = CWE_INFO["CWE-1395"]
    for rel, eco, desc in SCA_MANIFESTS:
        if not (REPO / rel).is_file():
            continue
        out.append({
            "id": new_id("SCA"),
            "analysis": "static",
            "scanner_types": ["SCA"],
            "language": eco,
            "cwe": cwe_entry("CWE-1395", name_1395),
            "expected_cwe": "CWE-1395",
            "title": f"CWE-1395: vulnerable {eco} dependencies",
            "severity": sev_1395,
            "location": {"file": rel, "start_line": 1, "snippet": ""},
            "patched": None,
            "description": desc,
            "status": "open",
        })
    # Source-level SAST sinks inside pipeline projects (e.g. bumpy's yaml.load)
    for rel, language, cwe, desc, snippet in PIPELINE_SAST:
        if not (REPO / rel).is_file():
            continue
        canonical, severity = CWE_INFO.get(cwe, ("", "Medium"))
        out.append({
            "id": new_id("SAST"),
            "analysis": "static",
            "scanner_types": ["SAST"],
            "language": language,
            "cwe": cwe_entry(cwe, canonical),
            "expected_cwe": cwe,
            "title": f"{cwe}: {canonical}",
            "severity": severity,
            "location": {"file": rel, "start_line": 1, "snippet": snippet},
            "patched": None,
            "description": desc,
            "status": "open",
        })
    # CI files — one positive per distinct CWE mentioned in the file's comments
    ci_base = REPO / "pipeline" / "ci"
    if ci_base.is_dir():
        for p in sorted(ci_base.rglob("*.yml")):
            text = p.read_text(encoding="utf-8", errors="replace")
            cwes = sorted({f"CWE-{m}" for m in CWE_RE.findall(text)}, key=lambda c: int(c.split("-")[1]))
            platform = "github" if ".github" in str(p) else "gitlab"
            for cwe in cwes:
                name, sev = CWE_INFO.get(cwe, ("", "Medium"))
                out.append({
                    "id": new_id("PIPELINE"),
                    "analysis": "static",
                    "scanner_types": ["PIPELINE"],
                    "language": platform,
                    "cwe": cwe_entry(cwe, name),
                    "expected_cwe": cwe,
                    "title": f"{cwe}: {name}",
                    "severity": sev,
                    "location": {"file": str(p.relative_to(REPO)), "start_line": 1, "snippet": ""},
                    "patched": None,
                    "description": f"Insecure CI/CD configuration ({platform}) exhibiting {cwe}.",
                    "status": "open",
                })
    return out


def skills_fixtures() -> tuple[list[dict], list[dict]]:
    """Authored skill verdicts (src/skills_labels.json) joined with the tree.
    label=flag -> positive; label=benign -> negative."""
    data = json.loads((SRC / "skills_labels.json").read_text(encoding="utf-8")).get("fixtures", [])
    positives, negatives = [], []
    for f in data:
        skill_md = f"{f['dir']}/SKILL.md"
        if not (REPO / skill_md).is_file():
            continue
        if f["label"] == "flag":
            positives.append({
                "id": new_id("SKILL"),
                "analysis": "skill",
                "scanner_types": f.get("scanner_types", ["SKILL"]),
                "language": "skill",
                "cwe": [],
                "expected_cwe": None,
                "category": f["category"],
                "title": f"SKILL: {f['category']}",
                "severity": f.get("severity") or "Medium",
                "location": {"file": skill_md, "start_line": 1, "snippet": ""},
                "patched": None,
                "lure": f.get("lure"),
                "indicators": f.get("indicators", []),
                "description": "; ".join(f.get("indicators", [])),
                "status": "open",
            })
        else:
            negatives.append({
                "id": new_id("FP-SKILL"),
                "kind": f.get("kind", "benign"),
                "expect": "no-finding",
                "scanner_types": f.get("scanner_types", ["SKILL"]),
                "language": "skill",
                "file": skill_md,
                "resembles": f.get("resembles", ""),
                "reason": f.get("reason", ""),
            })
    return positives, negatives


# --------------------------------------------------------------------------- #
# secrets/ — per-format fixtures, look-alikes and the per-rule catalogue
# --------------------------------------------------------------------------- #
SECRETS = REPO / "secrets"


def secrets_positives() -> list[dict]:
    """secrets/fixtures/CWE-<n>/<format>/vulnerable.<ext> — the path carries the CWE."""
    out = []
    base = SECRETS / "fixtures"
    for vuln in sorted(base.rglob("vulnerable.*")):
        parts = vuln.relative_to(base).parts  # (CWE-<n>, <format>, vulnerable.<ext>)
        if len(parts) != 3 or not CWE_RE.search(parts[0]):
            continue
        cwe, fmt = f"CWE-{CWE_RE.search(parts[0]).group(1)}", parts[1]
        canonical, severity = CWE_INFO.get(cwe, ("", "Medium"))
        hdr = parse_header(vuln)
        scanners = ["SECRET"]
        if LANG_SCANNER.get(fmt, "SECRET") != "SECRET":
            scanners.append(LANG_SCANNER[fmt])
        patched = vuln.with_name(f"patched{vuln.suffix}")
        out.append({
            "id": new_id("SECRET"),
            "analysis": "static",
            "scanner_types": scanners,
            "language": fmt,
            "cwe": cwe_entry(cwe, canonical or hdr["name"]),
            "expected_cwe": cwe,
            "title": f"{cwe}: {hdr['name'] or canonical}",
            "severity": severity,
            "location": {"file": str(vuln.relative_to(REPO)), "start_line": 1, "snippet": hdr["sink"]},
            "patched": str(patched.relative_to(REPO)) if patched.exists() else None,
            "description": hdr["description"],
            "status": "open",
        })
    return out


EXT_SCANNER = {
    ".java": "SAST", ".c": "SAST", ".cpp": "SAST", ".cs": "SAST",
    ".py": "SAST", ".js": "SAST", ".ts": "SAST", ".jsx": "SAST", ".tsx": "SAST",
    ".tf": "IAC", ".yml": "IAC", ".yaml": "IAC",
    ".env": "SECRET", ".ini": "SECRET", ".conf": "SECRET", ".pem": "SECRET",
}


def secrets_negatives() -> list[dict]:
    out: list[dict] = []
    n = 0
    base = SECRETS / "fixtures"
    for patched in sorted(base.rglob("patched.*")):
        parts = patched.relative_to(base).parts
        if len(parts) != 3:
            continue
        n += 1
        out.append({
            "id": f"FP-SECRET-{n:03d}",
            "kind": "remediation",
            "expect": "no-finding",
            "scanner_types": ["SECRET"],
            "language": parts[1],
            "file": str(patched.relative_to(REPO)),
            "resembles": f"the remediated form of {parts[0]} ({parts[1]})",
            "reason": "Remediated counterpart of the vulnerable fixture; should be clean.",
        })
    fp_dir = SECRETS / "false-positives"
    if fp_dir.is_dir():
        for p in sorted(fp_dir.iterdir()):
            if not p.is_file() or p.name == "README.md":
                continue
            n += 1
            hdr = _fp_header(p)
            out.append({
                "id": f"FP-SECRET-{n:03d}",
                "kind": "lookalike",
                "expect": "no-finding",
                "scanner_types": [EXT_SCANNER.get(p.suffix, "SECRET")],
                "language": p.suffix.lstrip(".") or "txt",
                "file": str(p.relative_to(REPO)),
                "resembles": hdr["resembles"] or "a secret-detection rule",
                "reason": hdr["reason"] or "Benign code that only looks like a secret.",
            })
    return out


# --------------------------------------------------------------------------- #
# projects/ — whole applications, ground truth authored in dataset/<lang>.json
# --------------------------------------------------------------------------- #
DATASET = REPO / "dataset"
LINE_TOLERANCE = 3   # a finding within ±N lines of the anchored line counts as a hit


class DatasetError(ValueError):
    pass


def resolve_anchor(root: Path, rel: str, anchor: str, ctx: str) -> int:
    """1-based line of the unique line containing `anchor` in root/rel."""
    path = root / rel
    if not path.is_file():
        raise DatasetError(f"{ctx}: file not found: {path.relative_to(REPO)}")
    hits = [i for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1)
            if anchor in line]
    if len(hits) != 1:
        raise DatasetError(f"{ctx}: anchor {anchor!r} matches {len(hits)} lines in {path.relative_to(REPO)}")
    return hits[0]


def _loc(root: Path, ref: dict, ctx: str) -> dict:
    line = resolve_anchor(root, ref["file"], ref["anchor"], ctx)
    return {"file": str((root / ref["file"]).relative_to(REPO)), "start_line": line,
            "snippet": ref["anchor"]}


def project_fixtures() -> tuple[list[dict], list[dict], list[dict]]:
    """Read every dataset/<lang>.json. Returns (positives, negatives, apps).

    Each weakness becomes one positive located at its sink (+ optional `source`
    and `related` locations a scanner may legitimately report instead). Its
    `patched` counterpart and every `decoy` become negatives (must-not-flag)."""
    positives: list[dict] = []
    negatives: list[dict] = []
    apps: list[dict] = []
    errors: list[str] = []
    for spec_path in sorted(DATASET.glob("*.json")):
        if spec_path.name == "lint.json":
            continue
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        lang = spec["language"]
        app, fixed = REPO / spec["app"], REPO / spec["patched"]
        apps.append({"language": lang, "app": spec["app"], "patched": spec["patched"],
                     "runtime": spec.get("runtime", {}), "dataset": str(spec_path.relative_to(REPO))})
        for w in spec.get("weaknesses", []):
            ctx = f"{spec_path.name}:{w['id']}"
            try:
                sink = _loc(app, w, ctx)
                extra = [_loc(app, r, ctx) for r in ([w["source"]] if w.get("source") else []) + w.get("related", [])]
                fix = _loc(fixed, w["patched"], ctx + " (patched)") if w.get("patched") else None
            except DatasetError as exc:
                errors.append(str(exc))
                continue
            cwe = w["cwe"]
            canonical, severity = CWE_INFO.get(cwe, ("", "Medium"))
            types = w.get("scanner_types") or ["SAST"]
            entry = {
                "id": w["id"],
                "analysis": "static",
                "scanner_types": types,
                "language": lang,
                "cwe": cwe_entry(cwe, canonical) + [{"id": c, "name": CWE_INFO.get(c, ("", ""))[0]}
                                                    for c in w.get("also_cwe", [])],
                "expected_cwe": cwe,
                "title": f"{cwe}: {w.get('title') or canonical}",
                "severity": w.get("severity") or severity,
                "location": sink,
                "alt_locations": extra,
                "pattern": w.get("pattern", "direct"),
                "endpoint": w.get("endpoint"),
                "patched": fix,
                "description": w.get("description", ""),
                "status": "open",
            }
            static_types = [x for x in types if x != "DAST"]
            if static_types:
                positives.append({**entry, "scanner_types": static_types})
            if "DAST" in types and w.get("endpoint"):
                positives.append({**entry, "id": w["id"] + "-dast", "analysis": "dynamic",
                                  "scanner_types": ["DAST"],
                                  "location": {**sink, "endpoint": w["endpoint"]}})
            if fix:
                negatives.append({
                    "id": f"FP-{w['id']}", "kind": "remediation", "expect": "no-finding",
                    "scanner_types": [t for t in types if t != "DAST"] or ["SAST"],
                    "language": lang, "file": fix["file"], "start_line": fix["start_line"],
                    "expected_cwe": cwe,
                    "resembles": f"{cwe} at {sink['file']}:{sink['start_line']}",
                    "reason": w.get("fix", "Remediated counterpart in the patched application."),
                })
        for d in spec.get("decoys", []):
            ctx = f"{spec_path.name}:{d['id']}"
            for root in (app, fixed):
                try:
                    loc = _loc(root, d, ctx)
                except DatasetError as exc:
                    errors.append(str(exc))
                    continue
                negatives.append({
                    "id": f"FP-{d['id']}" + ("-patched" if root == fixed else ""),
                    "kind": "lookalike", "expect": "no-finding",
                    "scanner_types": d.get("scanner_types", ["SAST"]),
                    "language": lang, "file": loc["file"], "start_line": loc["start_line"],
                    "expected_cwe": d.get("resembles"),
                    "resembles": d.get("resembles", ""), "reason": d.get("reason", ""),
                })
        for dep in spec.get("dependencies", []):
            ctx = f"{spec_path.name}:{dep['id']}"
            try:
                loc = _loc(app, {"file": dep["manifest"], "anchor": dep["anchor"]}, ctx)
            except DatasetError as exc:
                errors.append(str(exc))
                continue
            name_1395, sev_1395 = CWE_INFO["CWE-1395"]
            positives.append({
                "id": dep["id"], "analysis": "static", "scanner_types": ["SCA"],
                "language": lang, "cwe": cwe_entry("CWE-1395", name_1395),
                "expected_cwe": "CWE-1395",
                "title": f"CWE-1395: {dep['package']} {dep['version']}",
                "severity": dep.get("severity", sev_1395), "location": loc,
                "package": dep["package"], "version": dep["version"],
                "advisories": dep.get("advisories", []),
                "reachable": dep.get("reachable"),
                "pattern": "reachable-dependency" if dep.get("reachable") else "unreachable-dependency",
                "patched": None, "description": dep.get("description", ""), "status": "open",
            })
    if errors:
        raise SystemExit("dataset errors:\n  " + "\n  ".join(errors))
    return positives, negatives, apps


# --------------------------------------------------------------------------- #
# projects/ structure + "no hint in app" checks (rules in dataset/lint.json)
# --------------------------------------------------------------------------- #
_COMMENT_RES = [
    re.compile(r"//\s?(.*)$"),                   # C-family line comment
    re.compile(r"#(?:\s(.*)|$)"),                # shell / python / ruby / yaml (not #include, #define…)
    re.compile(r"(?<!<!)--\s(.*)$"),             # SQL line comment (not the XML opener)
    re.compile(r"^\s*;\s?(.*)$"),                # ini comment (line start, not a C statement end)
    re.compile(r"/\*(.*?)(?:\*/|$)"),             # block comment start / one-liner
    re.compile(r"^\s*\*\s?(.*)$"),                # block comment continuation
    re.compile(r"<!--(.*?)(?:-->|$)"),            # HTML / XML
    re.compile(r"^\s*(?:\"\"\"|''')(.*)$"),       # python docstring line
]
OPENAPI_NAMES = ("openapi.yml", "openapi.yaml", "openapi.json", "swagger.yml", "swagger.yaml", "swagger.json")


def _load_lint() -> dict:
    p = DATASET / "lint.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}


def _iter_text_files(root: Path, cfg: dict):
    exts = tuple(cfg.get("text_extensions", []))
    skip = set(cfg.get("skip_dirs", []))
    for p in sorted(root.rglob("*")):
        if not p.is_file() or skip & set(p.relative_to(root).parts[:-1]):
            continue
        if p.name in exts or p.suffix in exts:
            yield p


def _comment_text(line: str) -> str:
    out = []
    for rx in _COMMENT_RES:
        m = rx.search(line)
        if m and m.group(1):
            out.append(m.group(1))
    return " ".join(out)


def _strip_allowed(text: str, allow: list[str]) -> str:
    for a in allow:
        text = text.replace(a, "")
    return text


def lint_hints(app: Path, cfg: dict) -> list[str]:
    """Words that would tell a reader (human or LLM) where the weaknesses are."""
    anywhere = [re.compile(x, re.IGNORECASE) for x in cfg.get("anywhere", [])]
    comments = [re.compile(x, re.IGNORECASE) for x in cfg.get("comments", [])]
    allow = cfg.get("allow", [])
    errs: list[str] = []
    for p in sorted(app.rglob("*")):
        rel = str(p.relative_to(app))
        if any(rx.search(rel) for rx in anywhere):
            errs.append(f"{app.relative_to(REPO)}/{rel}: file name gives a hint")
    for p in _iter_text_files(app, cfg):
        is_doc = p.suffix in (".md", ".txt")
        for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            text = _strip_allowed(line, allow)
            hit = next((rx.pattern for rx in anywhere if rx.search(text)), None)
            if not hit:
                ctext = text if is_doc else _comment_text(text)
                hit = next((rx.pattern for rx in comments if ctext and rx.search(ctext)), None)
            if hit:
                errs.append(f"{p.relative_to(REPO)}:{n}: hint /{hit}/ in: {line.strip()[:100]}")
    return errs


def check_structure(root: Path, runtime: dict, cfg: dict) -> list[str]:
    """A complete, runnable application: README (overview/build/run/urls/api docs),
    Dockerfile and an OpenAPI document."""
    rel = root.relative_to(REPO)
    if not root.is_dir():
        return [f"{rel}: missing directory"]
    errs = []
    if not (root / "Dockerfile").is_file():
        errs.append(f"{rel}: missing Dockerfile")
    if not any(root.rglob(n) for n in OPENAPI_NAMES):
        errs.append(f"{rel}: missing OpenAPI document ({', '.join(OPENAPI_NAMES)})")
    readme = root / "README.md"
    if not readme.is_file():
        return errs + [f"{rel}: missing README.md"]
    text = readme.read_text(encoding="utf-8", errors="replace")
    headings = [l.lstrip("#").strip() for l in text.splitlines() if l.startswith("#")]
    for topic, pats in cfg.get("readme", {}).get("required_sections", {}).items():
        if not any(re.search(pt, h, re.IGNORECASE) for h in headings for pt in pats):
            errs.append(f"{rel}/README.md: no section about '{topic}'")
    if not re.search(r"https?://(localhost|127\.0\.0\.1)", text):
        errs.append(f"{rel}/README.md: no local URL (http://localhost:<port>…)")
    if runtime.get("openapi") and runtime["openapi"] not in text:
        errs.append(f"{rel}/README.md: does not mention the OpenAPI URL {runtime['openapi']}")
    return errs


def check_projects(skip_lint: bool = False) -> None:
    cfg = _load_lint()
    errs: list[str] = []
    for spec_path in sorted(DATASET.glob("*.json")):
        if spec_path.name == "lint.json":
            continue
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        rt = spec.get("runtime", {})
        errs += check_structure(REPO / spec["app"], rt, cfg)
        errs += check_structure(REPO / spec["patched"], rt, cfg)
        if not skip_lint and (REPO / spec["app"]).is_dir():
            errs += lint_hints(REPO / spec["app"], cfg)
    if errs:
        raise SystemExit("projects checks failed (see dataset/lint.json; --skip-lint to bypass the hint check):\n  "
                         + "\n  ".join(errs))


def _parse_catalogue_file(p: Path) -> tuple[str, list[str], int]:
    name, detected, examples, section = "", [], 0, None
    for l in p.read_text(encoding="utf-8", errors="replace").splitlines():
        s = l.rstrip()
        if s.startswith("# Catalogue entry"):
            name = s.split(":", 1)[1].strip() if ":" in s else name
            section = None
        elif "Detected by this rule" in s:
            section = "detect"
        elif section == "detect" and s.startswith("#   - "):
            parts = s[6:].split()
            if len(parts) >= 2:
                detected.append(f"{parts[0]}:{parts[-1]}")
        elif s.startswith("#"):
            if section == "detect":
                section = None
        elif s.strip():
            examples += 1
    return name, detected, examples


def secret_catalogue() -> dict:
    cat = SECRETS / "catalogue"
    if not cat.is_dir():
        return {}
    files = sorted(cat.rglob("*.txt"))
    providers = sorted({f.parent.name for f in files})
    entries = []
    for i, p in enumerate(files, 1):
        name, detected, n_ex = _parse_catalogue_file(p)
        entries.append({
            "id": f"SEC-{i:04d}",
            "expected_cwe": "CWE-798",
            "scanner_types": ["SECRET"],
            "provider": p.parent.name,
            "rule": p.stem,
            "name": name,
            "file": str(p.relative_to(REPO)),
            "detected_by": detected,
            "examples": n_ex,
        })
    return {
        "dir": str(cat.relative_to(REPO)),
        "expected_cwe": "CWE-798",
        "scanner_types": ["SECRET"],
        "files": len(files),
        "providers": len(providers),
        "note": "One example secret per rule, grouped across scanners (kingfisher, "
                "titus, noseyparker, gitleaks, betterleaks). Every entry is a CWE-798 "
                "positive the SECRET scanners are expected to flag. See catalogue/README.md.",
        "entries": entries,
    }


# --------------------------------------------------------------------------- #
# Assemble + write one file per directory
# --------------------------------------------------------------------------- #
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _summary(positives: list[dict], negatives: list[dict], catalogue: dict | None) -> dict:
    by_analysis = Counter(f.get("analysis", "static") for f in positives)
    by_scanner = Counter(t for f in positives for t in f.get("scanner_types", []))
    by_sev = Counter(f.get("severity") for f in positives if f.get("severity"))
    by_lang = Counter(f.get("language") for f in positives)
    by_kind = Counter(n.get("kind", "") for n in negatives)
    s = {
        "positives": len(positives),
        "negatives": len(negatives),
        "by_analysis": dict(sorted(by_analysis.items())),
        "by_scanner_type": dict(sorted(by_scanner.items())),
        "by_severity": {k: by_sev.get(k, 0) for k in SEV_ORDER if by_sev.get(k)},
        "by_language": dict(sorted(by_lang.items())),
    }
    if negatives:
        s["negatives_by_kind"] = dict(sorted(by_kind.items()))
    if catalogue:
        s["secret_catalogue_files"] = catalogue.get("files", 0)
    return s


def write_theme(theme: str, *, title: str, scope: str, positives: list[dict],
                negatives: list[dict], catalogue: dict | None = None, note: str = "",
                extra: dict | None = None) -> dict:
    families = sorted({t for f in positives for t in f.get("scanner_types", [])})
    doc = {
        "schema_version": SCHEMA_VERSION,
        "theme": theme,
        "report": {
            "title": title,
            "scanner_families": families,
            "generated_by": "benchmark/src/build_report.py (derived from the fixtures)",
            "scope": scope,
            "fields": {
                "positives[]": "fixtures a scanner SHOULD detect; keyed by location.file",
                "positives[].scanner_types": "families able to detect it (SAST, IAC, PIPELINE, SECRET, DAST, SCA, SKILL)",
                "positives[].expected_cwe": "ground-truth CWE for benchmark/src/benchmark.py (null for skills — see category)",
                "positives[].alt_locations": "projects only: source / related lines a scanner may report instead of the sink",
                "positives[].pattern": "projects only: how the weakness is laid out (direct, inter-file, second-order, ...)",
                "negatives[].start_line": "projects only: the must-not-flag line (patched sink or decoy)",
                "negatives[]": "fixtures a scanner should NOT flag; a report here is a false positive",
                "negatives[].kind": "remediation / lookalike / benign / benign-lookalike",
            },
            "severity_scale": SEV_ORDER,
            "note": note or "Re-run benchmark/src/build_report.py after adding/removing fixtures.",
        },
        "summary": _summary(positives, negatives, catalogue),
        "positives": positives,
        "negatives": negatives,
    }
    if catalogue:
        doc["secret_catalogue"] = catalogue
    if extra:
        doc.update(extra)
    out = REPO / "benchmark" / "ground-truth" / f"{theme}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"  {out.relative_to(REPO)} — {len(positives)} positives, {len(negatives)} negatives"
          + (f", {catalogue['files']} catalogue files" if catalogue else ""))
    return doc


def write_inventory(themes: dict[str, dict]) -> None:
    """benchmark/INVENTORY.md — human recap, regenerated with the ground truth."""
    L = ["# Fixture inventory (generated)", "",
         "Generated by `benchmark/src/build_report.py` — do not edit by hand.", "",
         "## Totals per theme", "",
         "| Theme | Positives | Negatives | Notes |", "|---|--:|--:|---|"]
    for name, doc in themes.items():
        s = doc["summary"]
        note = ", ".join(f"{k} {v}" for k, v in s.get("by_scanner_type", {}).items())
        if s.get("secret_catalogue_files"):
            note += f"; + {s['secret_catalogue_files']} catalogue files"
        L.append(f"| `{name}` | {s['positives']} | {s['negatives']} | {note} |")
    proj = themes.get("projects", {})
    pos = [f for f in proj.get("positives", []) if f.get("analysis") == "static"]
    langs = sorted({f["language"] for f in pos})
    L += ["", "## projects — CWE × language", ""]
    if not pos:
        L.append("No application yet — see `projects/README.md` and `dataset/README.md`.")
    else:
        L.append("Number of weaknesses per CWE and language (static positives, incl. SCA).")
        L.append("")
        L.append("| CWE | Name | " + " | ".join(langs) + " |")
        L.append("|---|---|" + "|".join([":-:"] * len(langs)) + "|")
        by: dict[str, Counter] = {}
        for f in pos:
            by.setdefault(f["expected_cwe"], Counter())[f["language"]] += 1
        for cwe in sorted(by, key=lambda c: int(c.split("-")[1])):
            row = " | ".join(str(by[cwe].get(lg, "·")) for lg in langs)
            L.append(f"| {cwe} | {CWE_INFO.get(cwe, ('', ''))[0]} | {row} |")
        pats = Counter(f.get("pattern", "direct") for f in pos)
        L += ["", "### By pattern", "", "| Pattern | Count |", "|---|--:|"]
        L += [f"| `{k}` | {v} |" for k, v in pats.most_common()]
        L += ["", "### Applications", "", "| Language | App | Patched | Weaknesses | DAST endpoints | Decoys |",
              "|---|---|---|--:|--:|--:|"]
        for a in proj.get("apps", []):
            n = sum(1 for f in pos if f["language"] == a["language"])
            d = sum(1 for f in proj["positives"] if f["language"] == a["language"] and f["analysis"] == "dynamic")
            dec = sum(1 for x in proj.get("negatives", []) if x["language"] == a["language"]
                      and x["kind"] == "lookalike" and not x["id"].endswith("-patched"))
            L.append(f"| {a['language']} | `{a['app']}` | `{a['patched']}` | {n} | {d} | {dec} |")
    out = REPO / "benchmark" / "INVENTORY.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"  {out.relative_to(REPO)}")


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--skip-lint", action="store_true",
                    help="do not fail on hint words found in projects/<lang>/app")
    args = ap.parse_args()
    check_projects(skip_lint=args.skip_lint)
    secret_pos = secrets_positives()
    pipeline_pos = pipeline_positives()
    project_pos, project_neg, apps = project_fixtures()
    skill_pos, skill_neg = skills_fixtures()

    print("Writing per-theme ground truth to benchmark/ground-truth/:")
    docs = {}
    docs["secrets"] = write_theme(
        "secrets",
        title="guinea-pig — hard-coded secrets (ground truth)",
        scope="Per-format secret fixtures (vulnerable/patched), the per-rule secret catalogue "
              "(one example per rule of secret-rules) and benign look-alikes.",
        positives=secret_pos, negatives=secrets_negatives(), catalogue=secret_catalogue(),
    )
    docs["projects"] = write_theme(
        "projects",
        title="guinea-pig — whole applications per language (ground truth)",
        scope="projects/<lang>/app (weaknesses) and projects/<lang>/app-patched (same app, fixed). "
              "Authored in dataset/<lang>.json, anchors resolved to lines. Static positives are graded "
              f"by file + line (±{LINE_TOLERANCE}); DAST positives by endpoint.",
        positives=project_pos, negatives=project_neg,
        extra={"apps": apps, "line_tolerance": LINE_TOLERANCE},
    )
    docs["pipeline"] = write_theme(
        "pipeline",
        title="guinea-pig — supply-chain (SCA) & CI/CD fixtures (ground truth)",
        scope="Whole-file manifests pinned to vulnerable dependencies (CWE-1395), the bumpy pyyaml "
              "project (CWE-1395 + CWE-502 yaml.load sinks), and insecure CI/CD configs (one positive "
              "per CWE per file).",
        positives=pipeline_pos, negatives=[],
    )
    docs["skills"] = write_theme(
        "skills",
        title="guinea-pig — Agent skill-scanner fixtures (ground truth)",
        scope="Malicious Agent-skill fixtures a skill scanner SHOULD flag, plus benign / benign-lookalike "
              "skills it should NOT. CWE doesn't apply — see positives[].category and indicators.",
        positives=skill_pos, negatives=skill_neg,
        note="Verdicts/categories are authored in benchmark/src/skills_labels.json (the SKILL.md files carry "
             "no in-file marker by design). exfil targets are neutralised to localhost.",
    )
    write_inventory(docs)
    total = len(secret_pos) + len(project_pos) + len(pipeline_pos) + len(skill_pos)
    print(f"Total: {total} positives (secrets={len(secret_pos)}, projects={len(project_pos)}, "
          f"pipeline={len(pipeline_pos)}, skills={len(skill_pos)}) across {len(apps)} applications.")

if __name__ == "__main__":
    main()