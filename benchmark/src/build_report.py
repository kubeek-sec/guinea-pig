#!/usr/bin/env python3
"""Generate the uniform per-theme ground-truth catalogs from the fixtures.

Single source of truth for the benchmark. Writes one ``benchmark/ground-truth/<theme>.json``
per fixture family, all sharing the same schema:

    benchmark/ground-truth/static.json     SAST / IAC / PIPELINE / SECRET source fixtures (+ secret_catalogue)
    benchmark/ground-truth/pipeline.json   SCA manifests + CI/CD configs (+ the bumpy pyyaml project)
    benchmark/ground-truth/dynamic.json    DAST endpoints (dynamic/app.js, graded by endpoint)
    benchmark/ground-truth/llm.json        context-stripped UUID twins (source backref held in src/llm_sources.json)
    benchmark/ground-truth/skills.json     malicious / benign Agent-skill fixtures (labels in src/skills_labels.json)

Common envelope::

    { schema_version, directory, report, summary, positives[], negatives[] [, secret_catalogue] }

`positives` are expected to be detected; `negatives` are expected to stay clean.
Derived mechanically from the fixture tree plus two irreducible sidecars in this
directory (the opaque llm UUID->source map and the authored skill verdicts).
Re-run after adding/removing fixtures::

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
SCHEMA_VERSION = "5.0"

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
# Header parsing (static fixtures + look-alikes)
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
def static_positives() -> list[dict]:
    out = []
    base = REPO / "static"
    for vuln in sorted(base.rglob("vulnerable.*")):
        parts = vuln.relative_to(base).parts  # (CWE-<n>, <language>, vulnerable.<ext>)
        if len(parts) != 3:
            continue
        cwe_dir, language = parts[0], parts[1]
        m = CWE_RE.search(cwe_dir)
        if not m:
            continue
        cwe = f"CWE-{m.group(1)}"
        canonical, severity = CWE_INFO.get(cwe, ("", "Medium"))
        hdr = parse_header(vuln)
        scanners = [LANG_SCANNER.get(language, "SAST")]
        if cwe in SECRET_ALSO and "SECRET" not in scanners:
            scanners.append("SECRET")
        patched = vuln.with_name(f"patched{vuln.suffix}")
        out.append({
            "id": new_id(scanners[0]),
            "analysis": "static",
            "scanner_types": scanners,
            "language": language,
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


def dynamic_positives() -> list[dict]:
    """Parse dynamic/openapi.yml for x-cwe annotations (no yaml dependency)."""
    spec = REPO / "dynamic" / "openapi.yml"
    if not spec.is_file():
        return []
    out = []
    current_path = None
    pending: dict = {}
    for raw in spec.read_text(encoding="utf-8").splitlines():
        mp = re.match(r"^  (/[^:]*):\s*$", raw)
        if mp:
            current_path = mp.group(1)
            pending = {}
            continue
        if current_path is None:
            continue
        s = raw.strip()
        if s.startswith("x-cwe:"):
            pending["cwe"] = s.split(":", 1)[1].strip()
        elif s.startswith("x-vuln:"):
            pending["vuln"] = s.split(":", 1)[1].strip()
        elif s.startswith("summary:"):
            pending["summary"] = s.split(":", 1)[1].strip()
        if pending.get("cwe") and pending.get("vuln") and not pending.get("_done"):
            cwe = pending["cwe"]
            canonical, severity = CWE_INFO.get(cwe, ("", "Medium"))
            out.append({
                "id": new_id("DAST"),
                "analysis": "dynamic",
                "scanner_types": ["DAST"],
                "language": "http",
                "cwe": cwe_entry(cwe, canonical),
                "expected_cwe": cwe,
                "title": f"{cwe}: {pending.get('summary', current_path)}",
                "severity": severity,
                "location": {"file": "dynamic/app.js", "endpoint": current_path, "start_line": 1, "snippet": ""},
                "patched": None,
                "description": pending["vuln"],
                "status": "open",
            })
            pending["_done"] = True
    return out


def llm_positives(by_source: dict[str, list[dict]]) -> list[dict]:
    """Join the irreducible UUID->source map with the freshly-built positives of
    each source file. Each context-stripped llm twin inherits one positive entry
    per weakness of its source (a CI file / the DAST app contribute several)."""
    rows = json.loads((SRC / "llm_sources.json").read_text(encoding="utf-8")).get("rows", [])
    out = []
    for row in rows:
        src = row["source"]
        for base in by_source.get(src, []):
            e = dict(base)                          # copy the source positive
            e["language"] = row["language"]         # llm twin's own (opaque) ext/lang
            loc = dict(base.get("location") or {})
            loc.pop("endpoint", None)
            loc["file"] = row["file"]
            e["location"] = loc
            e["patched"] = None
            e["source"] = src                        # held back from the model under test
            out.append(e)
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
# Negatives + secret catalogue (static only)
# --------------------------------------------------------------------------- #
EXT_SCANNER = {
    ".java": "SAST", ".c": "SAST", ".cpp": "SAST", ".cs": "SAST",
    ".py": "SAST", ".js": "SAST", ".ts": "SAST", ".jsx": "SAST", ".tsx": "SAST",
    ".tf": "IAC", ".yml": "IAC", ".yaml": "IAC",
    ".env": "SECRET", ".ini": "SECRET", ".conf": "SECRET", ".pem": "SECRET",
}


def static_negatives() -> list[dict]:
    out: list[dict] = []
    n = 0
    base = REPO / "static"
    for patched in sorted(base.rglob("patched.*")):
        parts = patched.relative_to(base).parts
        if len(parts) != 3:
            continue
        language = parts[1]
        n += 1
        out.append({
            "id": f"FP-{n:03d}",
            "kind": "remediation",
            "expect": "no-finding",
            "scanner_types": [LANG_SCANNER.get(language, "SAST")],
            "language": language,
            "file": str(patched.relative_to(REPO)),
            "resembles": f"the remediated form of {parts[0]} ({language})",
            "reason": "Remediated counterpart of the vulnerable fixture; should be clean.",
        })
    fp_dir = REPO / "static" / "CWE-798" / "false-positives"
    if fp_dir.is_dir():
        for p in sorted(fp_dir.iterdir()):
            if not p.is_file() or p.name == "README.md":
                continue
            n += 1
            hdr = _fp_header(p)
            out.append({
                "id": f"FP-{n:03d}",
                "kind": "lookalike",
                "expect": "no-finding",
                "scanner_types": [EXT_SCANNER.get(p.suffix, "SECRET")],
                "language": p.suffix.lstrip(".") or "txt",
                "file": str(p.relative_to(REPO)),
                "resembles": hdr["resembles"] or "a secret-detection rule",
                "reason": hdr["reason"] or "Benign code that only looks like a secret.",
            })
    return out


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
    cat = REPO / "static" / "CWE-798" / "catalogue"
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
                negatives: list[dict], catalogue: dict | None = None, note: str = "") -> dict:
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
                "positives[].source": "llm only: original annotated fixture, held back from the model under test",
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
    out = REPO / "benchmark" / "ground-truth" / f"{theme}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"  {out.relative_to(REPO)} — {len(positives)} positives, {len(negatives)} negatives"
          + (f", {catalogue['files']} catalogue files" if catalogue else ""))
    return doc


def main() -> None:
    static_pos = static_positives()
    pipeline_pos = pipeline_positives()
    dynamic_pos = dynamic_positives()

    # index every code-fixture positive by its file, for the llm join
    by_source: dict[str, list[dict]] = {}
    for f in static_pos + pipeline_pos + dynamic_pos:
        by_source.setdefault(f["location"]["file"], []).append(f)

    llm_pos = llm_positives(by_source)
    skill_pos, skill_neg = skills_fixtures()

    print("Writing per-theme ground truth to benchmark/ground-truth/:")
    write_theme(
        "static",
        title="guinea-pig — static source-code fixtures (ground truth)",
        scope="Intentionally-vulnerable source fixtures (SAST/IAC/PIPELINE/SECRET) plus their "
              "patched counterparts and benign look-alikes. Positives (+ secret_catalogue) must be "
              "detected; negatives must stay clean.",
        positives=static_pos, negatives=static_negatives(), catalogue=secret_catalogue(),
    )
    write_theme(
        "pipeline",
        title="guinea-pig — supply-chain (SCA) & CI/CD fixtures (ground truth)",
        scope="Whole-file manifests pinned to vulnerable dependencies (CWE-1395), the bumpy pyyaml "
              "project (CWE-1395 + CWE-502 yaml.load sinks), and insecure CI/CD configs (one positive "
              "per CWE per file).",
        positives=pipeline_pos, negatives=[],
    )
    write_theme(
        "dynamic",
        title="guinea-pig — DAST target endpoints (ground truth)",
        scope="Endpoints of the running Express service (dynamic/app.js), graded by endpoint rather "
              "than by file. See dynamic/openapi.yml (x-cwe per path).",
        positives=dynamic_pos, negatives=[],
        note="Endpoint-graded. The dynamic theme is launched and scored by endpoint, not by file.",
    )
    write_theme(
        "llm",
        title="guinea-pig — context-stripped LLM-eval fixtures (ground truth)",
        scope="UUID-renamed, comment/CWE-stripped twins of the code fixtures, so an LLM can only infer "
              "the weakness from the code itself. One positive per weakness; `source` points back to the "
              "original fixture and must NOT be shown to the model under test.",
        positives=llm_pos, negatives=[],
        note="The opaque UUID->source map is benchmark/src/llm_sources.json. Re-run build_report.py to resync.",
    )
    write_theme(
        "skills",
        title="guinea-pig — Agent skill-scanner fixtures (ground truth)",
        scope="Malicious Agent-skill fixtures a skill scanner SHOULD flag, plus benign / benign-lookalike "
              "skills it should NOT. CWE doesn't apply — see positives[].category and indicators.",
        positives=skill_pos, negatives=skill_neg,
        note="Verdicts/categories are authored in benchmark/src/skills_labels.json (the SKILL.md files carry "
             "no in-file marker by design). exfil targets are neutralised to localhost.",
    )

    total_pos = len(static_pos) + len(pipeline_pos) + len(dynamic_pos) + len(llm_pos) + len(skill_pos)
    print(f"Total: {total_pos} positives across 5 themes "
          f"(static={len(static_pos)}, pipeline={len(pipeline_pos)}, dynamic={len(dynamic_pos)}, "
          f"llm={len(llm_pos)}, skills={len(skill_pos)}).")


if __name__ == "__main__":
    main()