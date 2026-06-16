"""
Core logic for the airgap dependency gap analyzer.
Pure standard library only (so the shipped tool needs no pip installs).
"""
import io
import re
import json
import zipfile
import urllib.request
import urllib.error
from html.parser import HTMLParser
from xml.etree import ElementTree as ET

try:
    import tomllib  # py3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


# --------------------------------------------------------------------------
# PEP 503 normalization
# --------------------------------------------------------------------------
_NORM_RE = re.compile(r"[-_.]+")


def normalize(name: str) -> str:
    return _NORM_RE.sub("-", name.strip()).lower()


# --------------------------------------------------------------------------
# Requirement / dependency string parsing
# --------------------------------------------------------------------------
# name, optional [extras], optional version specifier, optional ; marker
_REQ_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"\s*(?:\[(?P<extras>[^\]]*)\])?"
    r"\s*(?P<spec>(?:[<>=!~]=?|===)\s*[^;#]+)?"
)


def parse_req_string(s: str):
    """Return (name, spec) from a single requirement string, or None."""
    s = s.strip()
    if not s:
        return None
    m = _REQ_RE.match(s)
    if not m:
        return None
    name = m.group("name")
    spec = (m.group("spec") or "").strip()
    return name, spec


def parse_requirements_txt(text: str):
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-"):
            # -r other.txt, -e ., --hash=..., etc. Capture editable VCS names loosely.
            if line.startswith(("-e", "--editable")):
                # best effort: pull #egg=name if present
                m = re.search(r"#egg=([A-Za-z0-9._-]+)", line)
                if m:
                    out.append((m.group(1), "", raw.strip()))
            continue
        if line.startswith(("git+", "http://", "https://", "file://")):
            m = re.search(r"#egg=([A-Za-z0-9._-]+)", line)
            if m:
                out.append((m.group(1), "", raw.strip()))
            continue
        # drop environment markers
        line = line.split(";", 1)[0].strip()
        parsed = parse_req_string(line)
        if parsed:
            out.append((parsed[0], parsed[1], raw.strip()))
    return out


def _poetry_caret_to_spec(v):
    if isinstance(v, dict):
        v = v.get("version", "")
    if not isinstance(v, str):
        return ""
    return v.strip()


def parse_pyproject(text: str):
    """Extract declared dependencies from PEP 621 and/or Poetry pyproject.toml."""
    out = []
    if tomllib is None:
        # crude fallback: scan for quoted "name spec" lines
        for m in re.finditer(r'"([A-Za-z0-9][A-Za-z0-9._-]*)\s*([<>=!~][^"]*)?"', text):
            out.append((m.group(1), (m.group(2) or "").strip(), m.group(0)))
        return out
    data = tomllib.loads(text)

    # PEP 621
    proj = data.get("project", {})
    for dep in proj.get("dependencies", []) or []:
        p = parse_req_string(dep)
        if p:
            out.append((p[0], p[1], dep))
    for group, deps in (proj.get("optional-dependencies", {}) or {}).items():
        for dep in deps or []:
            p = parse_req_string(dep)
            if p:
                out.append((p[0], p[1], f"[{group}] {dep}"))

    # PEP 735 dependency-groups
    for group, deps in (data.get("dependency-groups", {}) or {}).items():
        for dep in deps or []:
            if isinstance(dep, str):
                p = parse_req_string(dep)
                if p:
                    out.append((p[0], p[1], f"[{group}] {dep}"))

    # Poetry
    tool = data.get("tool", {})
    poetry = tool.get("poetry", {})
    for section in ("dependencies", "dev-dependencies"):
        for name, v in (poetry.get(section, {}) or {}).items():
            if name.lower() == "python":
                continue
            out.append((name, _poetry_caret_to_spec(v), f"{name} {v}"))
    for group, gdata in (poetry.get("group", {}) or {}).items():
        for name, v in (gdata.get("dependencies", {}) or {}).items():
            if name.lower() == "python":
                continue
            out.append((name, _poetry_caret_to_spec(v), f"[{group}] {name} {v}"))
    return out


def parse_environment_yml(text: str):
    """Best-effort conda environment.yml parser (handles the pip: subsection too)."""
    out = []
    in_deps = False
    in_pip = False
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^dependencies\s*:", stripped):
            in_deps = True
            continue
        if in_deps and re.match(r"^[A-Za-z0-9_]+\s*:", stripped) and not stripped.startswith("-"):
            in_deps = False
        if not in_deps:
            continue
        if stripped.startswith("- pip:"):
            in_pip = True
            continue
        if stripped.startswith("-"):
            item = stripped[1:].strip().strip('"').strip("'")
            if not item or item == "pip":
                continue
            # conda spec uses name=version=build or name>=x ; pip uses name==x
            item = re.split(r"\s+", item)[0]
            name = re.split(r"[<>=!~ ]", item, 1)[0]
            spec = item[len(name):].strip()
            if name:
                out.append((name, spec, stripped))
    return out


def parse_setup_cfg(text: str):
    out = []
    import configparser
    cp = configparser.ConfigParser()
    try:
        cp.read_string(text)
    except Exception:
        return out
    if cp.has_option("options", "install_requires"):
        for line in cp.get("options", "install_requires").splitlines():
            p = parse_req_string(line)
            if p:
                out.append((p[0], p[1], line.strip()))
    return out


def parse_uv_lock(text: str):
    """Parse a uv.lock file. Returns a list of (name, spec, raw) tuples,
    matching the contract used by the other parse_* functions."""
    # Preferred path: real TOML parse (Python 3.11+ has tomllib in the stdlib).
    try:
        import tomllib
        data = tomllib.loads(text)
    except ModuleNotFoundError:
        data = None  # Python < 3.11: fall back to the line scanner below.
 
    out = []
    if data is not None:
        for pkg in data.get("package", []) or []:
            name = pkg.get("name")
            if not name:
                continue
            src = pkg.get("source", {})
            if isinstance(src, dict) and any(k in src for k in ("editable", "virtual", "directory")):
                continue  # local project / workspace member, not from an index
            version = (pkg.get("version") or "").strip()
            spec = "==" + version if version else ""
            out.append((name, spec, (name + " " + version).strip()))
        return out
 
    # Fallback for environments without tomllib. uv.lock is line-oriented:
    # each package is a [[package]] block whose name/version/source scalars
    # appear at the top, before any arrays or [package.*] subtables.
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]:
        if re.search(r"(?m)^\s*source\s*=\s*\{\s*(?:editable|virtual|directory)\b", block):
            continue
        nm = re.search(r'(?m)^\s*name\s*=\s*"([^"]+)"', block)
        if not nm:
            continue
        vr = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', block)
        name = nm.group(1)
        version = vr.group(1) if vr else ""
        spec = "==" + version if version else ""
        out.append((name, spec, (name + " " + version).strip()))
    return out


def parse_dependency_file(filename: str, text: str):
    """Dispatch by filename. Returns list of (name, spec, raw)."""
    low = filename.lower()
    if low.endswith("uv.lock"):
        return parse_uv_lock(text)
    if low.endswith(".toml") or low == "pyproject.toml":
        return parse_pyproject(text)
    if low.endswith((".yml", ".yaml")):
        return parse_environment_yml(text)
    if low.endswith(".cfg"):
        return parse_setup_cfg(text)
    # default: treat as requirements.txt style
    return parse_requirements_txt(text)


# --------------------------------------------------------------------------
# Minimal .xlsx reader (zip of XML), standard library only
# --------------------------------------------------------------------------
_NS = {
    "main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "pr": "http://schemas.openxmlformats.org/package/2006/relationships",
}


def _col_to_index(ref: str) -> int:
    """A1 -> 0, B2 -> 1 ... letters portion to zero-based column index."""
    letters = "".join(ch for ch in ref if ch.isalpha())
    idx = 0
    for ch in letters:
        idx = idx * 26 + (ord(ch.upper()) - ord("A") + 1)
    return idx - 1


def read_xlsx(data: bytes):
    """Return dict: {sheet_name: [ [cell, cell, ...], ... ]} with cell text."""
    z = zipfile.ZipFile(io.BytesIO(data))

    # shared strings
    shared = []
    if "xl/sharedStrings.xml" in z.namelist():
        root = ET.fromstring(z.read("xl/sharedStrings.xml"))
        for si in root.findall("main:si", _NS):
            # concatenate all text nodes (handles rich text runs)
            shared.append("".join(t.text or "" for t in si.iter("{%s}t" % _NS["main"])))

    # map sheet name -> r:id  (workbook.xml)
    wb = ET.fromstring(z.read("xl/workbook.xml"))
    name_to_rid = {}
    for sh in wb.find("main:sheets", _NS).findall("main:sheet", _NS):
        rid = sh.get("{%s}id" % _NS["r"])
        name_to_rid[sh.get("name")] = rid

    # map r:id -> target file (workbook.xml.rels)
    rid_to_target = {}
    rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
    for rel in rels.findall("pr:Relationship", _NS):
        rid_to_target[rel.get("Id")] = rel.get("Target")

    sheets = {}
    for name, rid in name_to_rid.items():
        target = rid_to_target.get(rid)
        if not target:
            continue
        path = target if target.startswith("xl/") else "xl/" + target.lstrip("/")
        if path not in z.namelist():
            # some files use absolute-ish targets
            path = "xl/" + target.split("xl/")[-1]
        if path not in z.namelist():
            continue
        ws = ET.fromstring(z.read(path))
        rows_out = []
        sheetdata = ws.find("main:sheetData", _NS)
        if sheetdata is None:
            sheets[name] = rows_out
            continue
        for row in sheetdata.findall("main:row", _NS):
            cells = {}
            maxc = -1
            for c in row.findall("main:c", _NS):
                ref = c.get("r", "")
                ci = _col_to_index(ref) if ref else (maxc + 1)
                maxc = max(maxc, ci)
                t = c.get("t")
                v_el = c.find("main:v", _NS)
                if t == "s" and v_el is not None:
                    val = shared[int(v_el.text)]
                elif t == "inlineStr":
                    is_el = c.find("main:is", _NS)
                    val = "".join(x.text or "" for x in is_el.iter("{%s}t" % _NS["main"])) if is_el is not None else ""
                else:
                    val = v_el.text if v_el is not None else ""
                cells[ci] = val or ""
            row_list = [cells.get(i, "") for i in range(maxc + 1)]
            rows_out.append(row_list)
        sheets[name] = rows_out
    return sheets


# --------------------------------------------------------------------------
# Databricks runtime release-notes scraper
# --------------------------------------------------------------------------
class _TableParser(HTMLParser):
    """Collect tables (list of rows; each row a list of cell text) and the
    nearest preceding heading text for each table."""

    def __init__(self):
        super().__init__()
        self.tables = []          # list of (heading_text, rows)
        self._cur_rows = None
        self._cur_row = None
        self._cur_cell = None
        self._in_cell = False
        self._heading_buf = []
        self._in_heading = False
        self._last_heading = ""

    def handle_starttag(self, tag, attrs):
        if tag in ("h1", "h2", "h3", "h4"):
            self._in_heading = True
            self._heading_buf = []
        elif tag == "table":
            self._cur_rows = []
        elif tag == "tr" and self._cur_rows is not None:
            self._cur_row = []
        elif tag in ("td", "th") and self._cur_row is not None:
            self._in_cell = True
            self._cur_cell = []

    def handle_endtag(self, tag):
        if tag in ("h1", "h2", "h3", "h4"):
            self._in_heading = False
            self._last_heading = "".join(self._heading_buf).strip()
        elif tag == "table" and self._cur_rows is not None:
            self.tables.append((self._last_heading, self._cur_rows))
            self._cur_rows = None
        elif tag == "tr" and self._cur_row is not None:
            self._cur_rows.append(self._cur_row)
            self._cur_row = None
        elif tag in ("td", "th") and self._in_cell:
            self._cur_row.append("".join(self._cur_cell).strip())
            self._in_cell = False
            self._cur_cell = None

    def handle_data(self, data):
        if self._in_heading:
            self._heading_buf.append(data)
        if self._in_cell:
            self._cur_cell.append(data)


_VERSION_RE = re.compile(r"^v?\d+(\.\d+)*([.\-+][A-Za-z0-9.]+)?$")
_PKGNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _looks_like_version(s: str) -> bool:
    s = s.strip()
    return bool(_VERSION_RE.match(s)) or bool(re.match(r"^\d", s))


def extract_python_libs_from_html(html: str):
    """Find the installed-Python-libraries table(s) and return {norm_name: version}."""
    p = _TableParser()
    p.feed(html)
    libs = {}
    # Prefer tables whose heading mentions python; else accept lib/version tables
    # that are NOT under R / Scala / Java / NVIDIA headings.
    for heading, rows in p.tables:
        h = heading.lower()
        is_python = "python" in h
        is_other_lang = any(k in h for k in ("r librar", "scala", "java", "nvidia", "gpu"))
        # detect a library/version header row
        header = [c.lower() for c in rows[0]] if rows else []
        looks_libver = "library" in header and "version" in header
        if not (is_python or (looks_libver and not is_other_lang)):
            continue
        for row in rows:
            cells = [c for c in row]
            # skip header rows
            low = [c.lower() for c in cells]
            if low and low[0] in ("library", "package"):
                continue
            # Databricks packs multiple (lib, version) pairs per row
            for i in range(0, len(cells) - 1, 2):
                name = cells[i].strip()
                ver = cells[i + 1].strip()
                if not name:
                    continue
                if name.lower() in ("library", "package", "version"):
                    continue
                if _PKGNAME_RE.match(name) and (_looks_like_version(ver) or ver == ""):
                    libs[normalize(name)] = ver
    return libs


def _channel_base(channel: str) -> str:
    return {
        "aws": "https://docs.databricks.com/aws/en/release-notes/runtime/",
        "gcp": "https://docs.databricks.com/gcp/en/release-notes/runtime/",
        "azure": "https://learn.microsoft.com/en-us/azure/databricks/release-notes/runtime/",
    }.get(channel, "https://docs.databricks.com/aws/en/release-notes/runtime/")


def _fetch_libs(url: str, timeout: int):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (airgap-tool)"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        html = resp.read().decode("utf-8", "replace")
    return extract_python_libs_from_html(html)


def scrape_databricks(version: str, channel: str = "aws", timeout: int = 20):
    """
    Fetch the runtime release-notes page and return (url_used, {norm: ver}, error).
    For ML runtimes, the page lists only libraries that DIFFER from the base
    runtime, so we also fetch the base runtime and union it in (ML wins on
    version conflicts, since ML is built on top of base).
    """
    v = version.strip().lower().replace("databricks runtime", "").strip()
    is_lts = "lts" in v
    is_ml = bool(re.search(r"\bml\b", v)) or v.endswith("ml")
    num_m = re.search(r"\d+(\.\d+)?", v)
    num = num_m.group(0) if num_m else v
    base_url = _channel_base(channel)

    errors = []
    libs, url_used = {}, None

    # 1) the target page (ML or base, as requested)
    target_slug = num + ("lts" if is_lts else "")
    if is_ml:
        target_slug += "-ml" if is_lts else "ml"
    for slug in dict.fromkeys([target_slug, num + ("lts" if is_lts else ""), num + "lts", num]):
        url = base_url + slug
        try:
            got = _fetch_libs(url, timeout)
            if got:
                libs, url_used = got, url
                break
            errors.append(f"{url} (no Python library table found)")
        except urllib.error.HTTPError as e:
            errors.append(f"{url} (HTTP {e.code})")
        except Exception as e:  # noqa
            errors.append(f"{url} ({e.__class__.__name__})")

    # 2) for ML runtimes, union in the base runtime libraries
    if is_ml and libs:
        base_slug = num + ("lts" if is_lts else "")
        for slug in dict.fromkeys([base_slug, num + "lts", num]):
            url = base_url + slug
            try:
                base_libs = _fetch_libs(url, timeout)
                if base_libs:
                    for n, ver in base_libs.items():
                        libs.setdefault(n, ver)  # ML page wins on conflicts
                    url_used = f"{url_used} + {url} (base runtime)"
                    break
            except Exception:  # noqa
                continue

    if not libs:
        return None, {}, "; ".join(errors)
    return url_used, libs, None


def fetch_url_text(url: str, timeout: int = 20):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (airgap-tool)"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


# --------------------------------------------------------------------------
# Gap analysis
# --------------------------------------------------------------------------
_EXACT_PIN_RE = re.compile(r"^==\s*([^,;]+)$")


def analyze(excel_packages, dbr_libs, repo_deps):
    """
    excel_packages: list of (name, version) from the hosted-pip sheet
    dbr_libs:       {norm_name: version} scraped/loaded from Databricks
    repo_deps:      list of dicts {name, spec, raw, source}
    Returns a report dict.
    """
    available = {}   # norm -> {"version":..., "sources": set()}
    for name, ver in excel_packages:
        if not name:
            continue
        n = normalize(name)
        rec = available.setdefault(n, {"version": "", "sources": set()})
        if ver and not rec["version"]:
            rec["version"] = ver
        rec["sources"].add("hosted pip")
    for n, ver in dbr_libs.items():
        rec = available.setdefault(n, {"version": "", "sources": set()})
        if ver and not rec["version"]:
            rec["version"] = ver
        rec["sources"].add("Databricks Runtime")

    missing, mismatches, satisfied = [], [], []
    seen = set()
    for dep in repo_deps:
        n = normalize(dep["name"])
        if n in seen:
            continue
        seen.add(n)
        if n not in available:
            missing.append(dep)
        else:
            avail_ver = available[n]["version"]
            spec = dep.get("spec", "")
            m = _EXACT_PIN_RE.match(spec.strip()) if spec else None
            if m and avail_ver and normalize(m.group(1)) != normalize(avail_ver):
                mismatches.append({**dep, "available_version": avail_ver,
                                   "sources": sorted(available[n]["sources"])})
            else:
                satisfied.append({**dep, "available_version": avail_ver,
                                  "sources": sorted(available[n]["sources"])})

    return {
        "available_count": len(available),
        "hosted_count": sum(1 for r in available.values() if "hosted pip" in r["sources"]),
        "dbr_count": len(dbr_libs),
        "required_count": len(seen),
        "missing": missing,
        "mismatches": mismatches,
        "satisfied": satisfied,
    }


# ==========================================================================
# Local web server + browser UI  (standard library only)
# ==========================================================================
import base64
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _dbr_from_offline(text: str):
    """Accept either release-notes HTML or a requirements.txt paste."""
    if re.search(r"<\s*(table|td|html|tr)\b", text, re.I):
        return extract_python_libs_from_html(text)
    libs = {}
    for name, spec, _raw in parse_requirements_txt(text):
        ver = ""
        m = _EXACT_PIN_RE.match(spec.strip()) if spec else None
        if m:
            ver = m.group(1).strip()
        libs[normalize(name)] = ver
    return libs


def run_analysis(payload):
    excel_packages = [(p[0], p[1] if len(p) > 1 else "") for p in payload.get("excel_packages", [])]

    # Databricks libraries: offline paste wins; else scrape live.
    dbr_libs, dbr_source, dbr_error = {}, "", None
    offline = (payload.get("dbr_offline_text") or "").strip()
    version = (payload.get("dbr_version") or "").strip()
    channel = payload.get("dbr_channel") or "aws"
    if offline:
        dbr_libs = _dbr_from_offline(offline)
        dbr_source = f"pasted offline data ({len(dbr_libs)} libraries)"
    elif version:
        url, dbr_libs, dbr_error = scrape_databricks(version, channel)
        dbr_source = url or "not found"

    # Repo dependency files (uploaded/pasted) + fetched URLs
    repo_deps = []
    files = list(payload.get("repo_files", []))
    for u in payload.get("repo_urls", []):
        u = u.strip()
        if not u:
            continue
        try:
            txt = fetch_url_text(u)
            fname = u.rstrip("/").split("/")[-1] or "requirements.txt"
            files.append({"filename": fname, "text": txt})
        except Exception as e:
            dbr_error = (dbr_error + "; " if dbr_error else "") + f"could not fetch {u}: {e.__class__.__name__}"
    for f in files:
        for name, spec, raw in parse_dependency_file(f.get("filename", "requirements.txt"), f.get("text", "")):
            repo_deps.append({"name": name, "spec": spec, "raw": raw, "source": f.get("filename", "")})

    report = analyze(excel_packages, dbr_libs, repo_deps)
    report["dbr_source"] = dbr_source
    report["dbr_error"] = dbr_error
    report["dbr_version"] = version
    return report


PAGE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Airgap dependency check</title>
<style>
:root{
  --bg:#e9edf2; --surface:#ffffff; --ink:#16202b; --muted:#5c6b7a;
  --line:#d4dbe3; --accent:#3a4fd6; --accent-ink:#26308f;
  --missing:#c1440e; --missing-bg:#fbeae1; --ok:#1f7a5a; --warn:#9a6b00; --warn-bg:#f7eed6;
  --mono:ui-monospace,"Cascadia Code","JetBrains Mono",Menlo,Consolas,monospace;
  --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.5;
  font-size:15px;padding:0 18px 80px}
@media (prefers-reduced-motion:no-preference){.reveal{animation:rise .4s ease both}}
@keyframes rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.wrap{max-width:880px;margin:0 auto}
header{padding:40px 0 22px;border-bottom:1px solid var(--line);margin-bottom:26px}
.eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.22em;text-transform:uppercase;
  color:var(--accent-ink);margin:0 0 10px}
h1{font-size:30px;line-height:1.12;margin:0;letter-spacing:-.01em;font-weight:680}
h1 .gate{color:var(--accent)}
.lede{color:var(--muted);margin:12px 0 0;max-width:62ch}
.station{background:var(--surface);border:1px solid var(--line);border-radius:12px;
  padding:20px 22px;margin:16px 0}
.station h2{font-size:15px;margin:0 0 4px;display:flex;align-items:baseline;gap:10px}
.num{font-family:var(--mono);font-size:12px;color:#fff;background:var(--accent);
  border-radius:6px;padding:2px 7px;letter-spacing:.04em}
.hint{color:var(--muted);font-size:13px;margin:0 0 16px}
label{display:block;font-weight:600;font-size:13px;margin:14px 0 5px}
input[type=text],select,textarea{width:100%;font-family:var(--mono);font-size:13px;
  border:1px solid var(--line);border-radius:8px;padding:9px 11px;background:#fbfcfe;color:var(--ink)}
textarea{resize:vertical;min-height:80px;line-height:1.45}
input[type=file]{font-size:13px}
.row{display:flex;gap:14px;flex-wrap:wrap}
.row>div{flex:1;min-width:170px}
.tabs{display:flex;gap:4px;margin:4px 0 12px;border-bottom:1px solid var(--line)}
.tab{font-family:var(--mono);font-size:12px;letter-spacing:.04em;padding:7px 12px;cursor:pointer;
  color:var(--muted);border:0;background:none;border-bottom:2px solid transparent;margin-bottom:-1px}
.tab[aria-selected=true]{color:var(--accent-ink);border-bottom-color:var(--accent)}
.pane{display:none}.pane.on{display:block}
.chip{display:inline-flex;align-items:center;gap:7px;font-family:var(--mono);font-size:12px;
  background:#eef1f6;border:1px solid var(--line);border-radius:999px;padding:4px 6px 4px 11px;margin:5px 6px 0 0}
.chip button{border:0;background:#d9dee7;border-radius:50%;width:17px;height:17px;cursor:pointer;
  color:var(--ink);font-size:12px;line-height:1}
button.act{font-family:var(--sans);font-weight:650;font-size:15px;border:0;border-radius:9px;
  background:var(--accent);color:#fff;padding:13px 24px;cursor:pointer;letter-spacing:.01em}
button.act:hover{background:var(--accent-ink)}
button.act:disabled{opacity:.5;cursor:wait}
button.ghost{font-family:var(--mono);font-size:12px;border:1px solid var(--line);background:#fbfcfe;
  border-radius:7px;padding:7px 11px;cursor:pointer;color:var(--accent-ink)}
button.ghost:hover{border-color:var(--accent)}
.go{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-top:6px}
.status{color:var(--muted);font-size:13px;font-family:var(--mono)}
.status.err{color:var(--missing)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}

/* results */
#out{margin-top:30px}
.summary{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px}
.stat{flex:1;min-width:120px;background:var(--surface);border:1px solid var(--line);
  border-radius:10px;padding:14px 16px}
.stat .n{font-family:var(--mono);font-size:26px;font-weight:680;line-height:1}
.stat .k{font-size:12px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.08em}
.stat.miss .n{color:var(--missing)} .stat.ok .n{color:var(--ok)}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:12px;
  overflow:hidden;margin:14px 0}
.panel.hero{border-color:var(--missing);box-shadow:0 1px 0 var(--missing)}
.phead{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:14px 18px;border-bottom:1px solid var(--line)}
.phead.hero{background:var(--missing-bg)}
.phead h3{margin:0;font-size:14px;display:flex;align-items:center;gap:9px}
.dot{width:9px;height:9px;border-radius:50%}
.dot.m{background:var(--missing)} .dot.w{background:var(--warn)} .dot.o{background:var(--ok)}
.plist{list-style:none;margin:0;padding:6px 0;max-height:none}
.plist li{display:flex;align-items:baseline;gap:12px;padding:7px 18px;border-top:1px solid #eef1f5;
  font-family:var(--mono);font-size:13px}
.plist li:first-child{border-top:0}
.pname{font-weight:650}
.pmeta{color:var(--muted);font-size:12px;margin-left:auto;text-align:right}
.tag{font-family:var(--mono);font-size:11px;padding:1px 6px;border-radius:5px;border:1px solid var(--line)}
.tag.dbr{color:var(--accent-ink)} .tag.pip{color:var(--ok)}
.empty{padding:18px;color:var(--muted);font-size:13px}
details summary{cursor:pointer;padding:13px 18px;font-size:13px;font-weight:600;color:var(--muted)}
.caveat{font-size:12.5px;color:var(--muted);border-left:2px solid var(--line);padding:2px 0 2px 14px;margin:22px 2px 0}
code{font-family:var(--mono);background:#eef1f6;padding:1px 5px;border-radius:4px;font-size:.92em}
.copied{color:var(--ok)!important}
</style>
</head>
<body>
<div class="wrap">
<header>
  <p class="eyebrow">airgap &middot; databricks runtime &middot; dependency reconciliation</p>
  <h1>What does this repo need that your airgap <span class="gate">doesn&rsquo;t have yet?</span></h1>
  <p class="lede">Combine your locally hosted pip inventory with the libraries baked into a Databricks
  Runtime version, then check a repo&rsquo;s declared dependencies against that combined set. The output is
  the shopping list of packages to carry across the gap.</p>
</header>

<!-- STATION 1 -->
<section class="station">
  <h2><span class="num">01</span> Airgap inventory</h2>
  <p class="hint">Two sources make up what&rsquo;s already available inside the airgap: your hosted pip list
  (the Excel file) and the libraries pre-installed in the Databricks Runtime.</p>

  <label>Hosted pip packages &mdash; Excel file (.xlsx)</label>
  <input type="file" id="xlsx" accept=".xlsx">
  <div class="row" id="xlsxPick" style="display:none">
    <div><label>Sheet / tab</label><select id="sheetSel"></select></div>
    <div><label>Package-name column</label><select id="colSel"></select></div>
    <div><label>Version column (optional)</label><select id="verSel"></select></div>
  </div>
  <p class="status" id="xlsxStatus"></p>

  <label>Databricks Runtime version</label>
  <div class="row">
    <div><input type="text" id="dbrVer" placeholder="e.g. 16.4 LTS  /  15.4 LTS ML  /  18.0"></div>
    <div><select id="dbrChan">
      <option value="aws">AWS docs</option>
      <option value="azure">Azure docs</option>
      <option value="gcp">GCP docs</option>
    </select></div>
  </div>
  <details style="margin-top:10px">
    <summary>Running inside the airgap? Paste the runtime libraries offline instead</summary>
    <p class="hint" style="padding:0 0 8px">Paste the release-notes HTML or a <code>requirements.txt</code>
    for the runtime. Used instead of fetching the docs site.</p>
    <textarea id="dbrOffline" placeholder="Paste release-notes HTML or requirements.txt here..."></textarea>
  </details>
</section>

<!-- STATION 2 -->
<section class="station">
  <h2><span class="num">02</span> Repo dependencies</h2>
  <p class="hint">What the git repo declares it needs. Add <code>requirements.txt</code>,
  <code>pyproject.toml</code>, <code>environment.yml</code>, or <code>setup.cfg</code> &mdash; or paste/point at a raw URL.</p>
  <div class="tabs" role="tablist">
    <button class="tab" role="tab" aria-selected="true" data-pane="pFile">Upload files</button>
    <button class="tab" role="tab" aria-selected="false" data-pane="pPaste">Paste</button>
    <button class="tab" role="tab" aria-selected="false" data-pane="pUrl">Raw URL</button>
  </div>
  <div class="pane on" id="pFile">
    <input type="file" id="depFiles" multiple
      accept=".txt,.toml,.cfg,.yml,.yaml,.in">
    <div id="fileChips"></div>
  </div>
  <div class="pane" id="pPaste">
    <label>Treat pasted text as</label>
    <select id="pasteKind">
      <option value="requirements.txt">requirements.txt</option>
      <option value="pyproject.toml">pyproject.toml</option>
      <option value="environment.yml">environment.yml</option>
      <option value="setup.cfg">setup.cfg</option>
    </select>
    <textarea id="depPaste" placeholder="numpy&#10;pandas>=2.0&#10;duckdb"></textarea>
  </div>
  <div class="pane" id="pUrl">
    <p class="hint" style="padding:0 0 6px">One raw file URL per line (e.g. a GitHub
    <code>raw.githubusercontent.com</code> link). Fetched by the local server, so no browser CORS issues.</p>
    <textarea id="depUrls" placeholder="https://raw.githubusercontent.com/org/repo/main/requirements.txt"></textarea>
  </div>
</section>

<!-- STATION 3 -->
<section class="station">
  <h2><span class="num">03</span> Run the check</h2>
  <div class="go">
    <button class="act" id="run">Find missing packages</button>
    <span class="status" id="runStatus"></span>
  </div>
</section>

<div id="out"></div>

<p class="caveat">This compares <strong>declared</strong> dependencies against your available set after
PEP&nbsp;503 name normalization (so <code>scikit_learn</code> and <code>scikit-learn</code> match). It does
<strong>not</strong> resolve the full transitive dependency tree, and version-range specifiers are reported
rather than fully evaluated &mdash; a package shown as available may still be the wrong version for a strict
pin. Treat the result as a starting manifest, not a guarantee.</p>
</div>

<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
let sheets={}, depFileList=[];

function abToB64(buf){let bin='';const b=new Uint8Array(buf),c=0x8000;
  for(let i=0;i<b.length;i+=c)bin+=String.fromCharCode.apply(null,b.subarray(i,i+c));return btoa(bin);}
async function post(url,body){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify(body)});return r.json();}

// tabs
$$('.tab').forEach(t=>t.onclick=()=>{$$('.tab').forEach(x=>x.setAttribute('aria-selected',x===t));
  $$('.pane').forEach(p=>p.classList.toggle('on',p.id===t.dataset.pane));});

// excel
$('#xlsx').onchange=async e=>{const f=e.target.files[0];if(!f)return;
  $('#xlsxStatus').textContent='Reading workbook...';$('#xlsxStatus').className='status';
  try{const b64=abToB64(await f.arrayBuffer());
    const res=await post('/api/inspect_excel',{xlsx_b64:b64});
    if(res.error)throw new Error(res.error);
    sheets=res.sheets;const names=Object.keys(sheets);
    $('#sheetSel').innerHTML=names.map(n=>`<option>${esc(n)}</option>`).join('');
    $('#xlsxPick').style.display='flex';pickSheet();
    $('#xlsxStatus').textContent=`Loaded ${names.length} tab(s).`;
  }catch(err){$('#xlsxStatus').textContent='Could not read file: '+err.message;$('#xlsxStatus').className='status err';}};
$('#sheetSel').onchange=pickSheet;
function pickSheet(){const rows=sheets[$('#sheetSel').value]||[];const hdr=rows[0]||[];
  const opts=hdr.map((h,i)=>`<option value="${i}">${esc(h||('column '+(i+1)))}</option>`).join('');
  $('#colSel').innerHTML=opts;
  $('#verSel').innerHTML=`<option value="-1">(none)</option>`+opts;
  // heuristic default: a column whose header looks like a package/name column
  const gi=hdr.findIndex(h=>/pack|name|librar|module|dependenc/i.test(h||''));
  if(gi>=0)$('#colSel').value=gi;
  const vi=hdr.findIndex(h=>/version|ver\b/i.test(h||''));
  if(vi>=0)$('#verSel').value=vi;
  countRows();}
$('#colSel').onchange=countRows;
function countRows(){const rows=sheets[$('#sheetSel').value]||[];
  $('#xlsxStatus').textContent=`${Math.max(0,rows.length-1)} package row(s) in this tab.`;}

function excelPackages(){const rows=sheets[$('#sheetSel').value]||[];if(!rows.length)return[];
  const ci=+$('#colSel').value, vi=+$('#verSel').value;
  const hdr=(rows[0]||[]).map(x=>(x||'').toString().toLowerCase().trim());
  const skipHeader=/pack|name|librar|module|dependenc/.test(hdr[ci]||'')|| hdr[ci]==='';
  const out=[];rows.forEach((r,idx)=>{if(idx===0&&skipHeader)return;
    const n=(r[ci]||'').toString().trim();if(!n)return;
    const v=vi>=0?(r[vi]||'').toString().trim():'';out.push([n,v]);});
  return out;}

// dep files
$('#depFiles').onchange=async e=>{for(const f of e.target.files){
  depFileList.push({filename:f.name,text:await f.text()});}
  e.target.value='';renderChips();};
function renderChips(){$('#fileChips').innerHTML=depFileList.map((f,i)=>
  `<span class="chip">${esc(f.filename)}<button data-i="${i}" title="remove">&times;</button></span>`).join('');
  $$('#fileChips .chip button').forEach(b=>b.onclick=()=>{depFileList.splice(+b.dataset.i,1);renderChips();});}

function esc(s){return (s==null?'':s.toString()).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}

// run
$('#run').onclick=async()=>{
  const files=[...depFileList];
  const paste=$('#depPaste').value.trim();
  if(paste)files.push({filename:$('#pasteKind').value,text:paste});
  const urls=$('#depUrls').value.split(/\n+/).map(s=>s.trim()).filter(Boolean);
  if(!files.length && !urls.length){setRun('Add at least one dependency source in station 02.',true);return;}
  const payload={
    excel_packages:excelPackages(),
    dbr_version:$('#dbrVer').value.trim(),
    dbr_channel:$('#dbrChan').value,
    dbr_offline_text:$('#dbrOffline').value.trim(),
    repo_files:files, repo_urls:urls
  };
  $('#run').disabled=true;setRun('Gathering inventory and checking dependencies...',false);
  try{const rep=await post('/api/analyze',payload);
    if(rep.error)throw new Error(rep.error);
    render(rep);setRun('',false);
  }catch(err){setRun('Error: '+err.message,true);}
  $('#run').disabled=false;};
function setRun(msg,err){const s=$('#runStatus');s.textContent=msg;s.className='status'+(err?' err':'');}

function srcTags(sources){return (sources||[]).map(s=>
  s==='Databricks Runtime'?'<span class="tag dbr">DBR</span>':'<span class="tag pip">hosted</span>').join(' ');}

function render(r){
  const o=$('#out');const m=r.missing||[],mm=r.mismatches||[],sat=r.satisfied||[];
  let dbrLine='';
  if(r.dbr_version||r.dbr_source){
    dbrLine = r.dbr_count
      ? `Databricks Runtime ${esc(r.dbr_version)} &mdash; ${r.dbr_count} libraries from ${esc(r.dbr_source)}.`
      : `<span style="color:var(--missing)">No Databricks libraries loaded${r.dbr_error?': '+esc(r.dbr_error):''}.</span>`;
  }
  o.innerHTML=`
  <div class="reveal">
  <div class="summary">
    <div class="stat miss"><div class="n">${m.length}</div><div class="k">Missing</div></div>
    <div class="stat"><div class="n">${mm.length}</div><div class="k">Version risk</div></div>
    <div class="stat ok"><div class="n">${sat.length}</div><div class="k">Available</div></div>
    <div class="stat"><div class="n">${r.available_count}</div><div class="k">In airgap</div></div>
  </div>
  ${dbrLine?`<p class="status" style="margin:-8px 2px 18px">${dbrLine}</p>`:''}

  <div class="panel hero">
    <div class="phead hero">
      <h3><span class="dot m"></span>Missing &mdash; must be added to the airgap</h3>
      ${m.length?`<button class="ghost" id="copyMiss">Copy as requirements.txt</button>`:''}
    </div>
    ${m.length?`<ul class="plist">`+m.map(d=>`<li>
        <span class="pname">${esc(d.name)}</span>
        ${d.spec?`<span class="pmeta">needs ${esc(d.spec)}</span>`:''}
        <span class="pmeta" style="opacity:.7">${esc(d.source||'')}</span></li>`).join('')+`</ul>`
      :`<p class="empty">Nothing missing &mdash; every declared dependency is already available inside the airgap.</p>`}
  </div>

  ${mm.length?`<div class="panel"><div class="phead"><h3><span class="dot w"></span>Available, but version may not satisfy the pin</h3></div>
    <ul class="plist">`+mm.map(d=>`<li><span class="pname">${esc(d.name)}</span>
      <span class="pmeta">repo wants ${esc(d.spec)} &middot; airgap has ${esc(d.available_version||'?')} ${srcTags(d.sources)}</span></li>`).join('')+`</ul></div>`:''}

  ${sat.length?`<div class="panel"><details><summary>${sat.length} dependencies already available &mdash; show</summary>
    <ul class="plist">`+sat.map(d=>`<li><span class="pname">${esc(d.name)}</span>
      <span class="pmeta">${d.available_version?esc(d.available_version)+' ':''}${srcTags(d.sources)}</span></li>`).join('')+`</ul></details></div>`:''}
  </div>`;

  const cm=$('#copyMiss');
  if(cm)cm.onclick=()=>{const txt=m.map(d=>d.name+(d.spec||'')).join('\n');
    navigator.clipboard.writeText(txt).then(()=>{cm.textContent='Copied';cm.classList.add('copied');
      setTimeout(()=>{cm.textContent='Copy as requirements.txt';cm.classList.remove('copied');},1600);});};
  o.scrollIntoView({behavior:'smooth',block:'start'});
}
</script>
</body>
</html>
'''


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet console
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body_json(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        try:
            data = self._body_json()
            if self.path == "/api/inspect_excel":
                raw = base64.b64decode(data["xlsx_b64"])
                sheets = read_xlsx(raw)
                self._send(200, {"sheets": sheets})
            elif self.path == "/api/analyze":
                self._send(200, run_analysis(data))
            else:
                self._send(404, {"error": "unknown endpoint"})
        except Exception as e:
            self._send(500, {"error": f"{e.__class__.__name__}: {e}"})


def main(port=8765, open_browser=True):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
    print(f"\n  Airgap dependency gap analyzer running at  {url}")
    print("  Press Ctrl+C to stop.\n")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        srv.shutdown()


if __name__ == "__main__":
    import sys
    p = 8765
    for a in sys.argv[1:]:
        if a.startswith("--port="):
            p = int(a.split("=", 1)[1])
    main(port=p, open_browser="--no-browser" not in sys.argv)
