#!/usr/bin/env python3

import argparse
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import shutil
from dataclasses import dataclass, field
from urllib.parse import urlparse

from datetime import datetime

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
except ImportError:
    class _Noop:
        BRIGHT = BLUE = GREEN = RED = YELLOW = CYAN = MAGENTA = WHITE = RESET_ALL = ""
    Fore = Style = _Noop()
    def colorama_init(): pass

VERSION = "1.0.0"

_BANNER = rf"""
{Fore.CYAN}{Style.BRIGHT}
 ██╗    ██╗ █████╗ ██████╗ ██████╗ ███████╗██████╗
 ██║    ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
 ██║ █╗ ██║███████║██████╔╝██████╔╝█████╗  ██████╔╝
 ██║███╗██║██╔══██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗
 ╚███╔███╔╝██║  ██║██║     ██║     ███████╗██║  ██║
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝{Style.RESET_ALL}
{Fore.WHITE} Web Technology Scanner v{VERSION}{Style.RESET_ALL}
"""

def _hline(char="─", width=60):
    return Fore.CYAN + char * width + Style.RESET_ALL

DATA_DIR = os.path.join(os.path.expanduser("~"), ".wappalyzer")
TECHNOLOGIES_FILE = os.path.join(DATA_DIR, "technologies.json")
TECH_BASE_URL = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src"


@dataclass
class PageData:
    url: str = ""
    html: str = ""
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    scripts: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    js: dict = field(default_factory=dict)
    dom: dict = field(default_factory=dict)
    text: str = ""
    xhr_urls: list = field(default_factory=list)
    cert_issuer: str = ""
    dns: dict = field(default_factory=dict)
    css_matches: set = field(default_factory=set)


class Pattern:
    __slots__ = ("string", "regex", "confidence", "version")

    def __init__(self, raw):
        self.string = ""
        self.regex = None
        self.confidence = 100
        self.version = None
        if not raw:
            return
        parts = raw.split("\\;")
        self.string = parts[0]
        try:
            self.regex = re.compile(self.string, re.I) if self.string else None
        except re.error:
            self.regex = re.compile(r"(?!x)x")
        for part in parts[1:]:
            kv = part.split(":", 1)
            if len(kv) == 2:
                if kv[0] == "confidence":
                    try: self.confidence = int(kv[1])
                    except ValueError: pass
                elif kv[0] == "version":
                    self.version = kv[1]

    def match(self, value):
        if value is None:
            return None
        if self.regex is None:
            return True
        return self.regex.search(str(value))


class Detection:
    __slots__ = ("confidence", "versions")

    def __init__(self):
        self.confidence = 0
        self.versions = set()

    def add(self, pattern, match=None):
        self.confidence = min(100, self.confidence + pattern.confidence)
        if not (pattern.version and match and hasattr(match, "groups") and match.groups()):
            return
        version = pattern.version
        for i, group in enumerate(match.groups()):
            ref = f"\\{i + 1}"
            ternary = re.search(rf"\\\\{i + 1}\?([^:]*):([^\\\\]*)", version)
            if group:
                if ternary:
                    version = version.replace(ternary.group(0), ternary.group(1))
                version = version.replace(ref, group)
            else:
                if ternary:
                    version = version.replace(ternary.group(0), ternary.group(2))
                version = version.replace(ref, "")
        version = re.sub(r"\\\d", "", version).strip()
        if version:
            self.versions.add(version)


def _ensure_list(val):
    if val is None: return []
    return val if isinstance(val, list) else [val]


class WappalyzerEngine:
    def __init__(self, technologies_file):
        with open(technologies_file) as f:
            data = json.load(f)
        self.categories = data["categories"]
        self.technologies = data["technologies"]
        self._js_paths = None
        self._dom_selectors = None
        self._css_selectors = None

    def get_js_paths(self):
        if self._js_paths is None:
            paths = set()
            for t in self.technologies.values():
                if "js" in t and isinstance(t["js"], dict):
                    paths.update(t["js"].keys())
            self._js_paths = sorted(paths)
        return self._js_paths

    def get_dom_selectors(self):
        if self._dom_selectors is None:
            sels = set()
            for t in self.technologies.values():
                dom = t.get("dom")
                if not dom: continue
                if isinstance(dom, str):
                    for s in dom.split(","): sels.add(s.strip())
                elif isinstance(dom, list):
                    for item in dom:
                        if isinstance(item, str):
                            for s in item.split(","): sels.add(s.strip())
                        elif isinstance(item, dict):
                            sels.update(item.keys())
                elif isinstance(dom, dict):
                    sels.update(dom.keys())
            sels.discard("")
            self._dom_selectors = sorted(sels)
        return self._dom_selectors

    def get_css_selectors(self):
        if self._css_selectors is None:
            sels = set()
            for t in self.technologies.values():
                for raw in _ensure_list(t.get("css", [])):
                    sels.add(raw.split("\\;")[0])
            self._css_selectors = sorted(sels)
        return self._css_selectors

    def _get_categories(self, tech):
        return [self.categories.get(str(n), {}).get("name", "") for n in tech.get("cats", [])]

    def analyze(self, pd):
        detected = {}
        for name, tech in self.technologies.items():
            det = self._check(tech, pd)
            if det.confidence > 0:
                detected[name] = {
                    "versions": sorted(det.versions),
                    "categories": self._get_categories(tech),
                    "confidence": det.confidence,
                }
        self._resolve_implies(detected)
        self._resolve_requires(detected)
        self._resolve_excludes(detected)
        return detected

    def _check(self, tech, pd):
        det = Detection()

        for raw in _ensure_list(tech.get("url", [])):
            p = Pattern(raw); m = p.match(pd.url)
            if m: det.add(p, m if m is not True else None)

        for hdr, raw in (tech.get("headers") or {}).items():
            val = pd.headers.get(hdr.lower())
            if val is not None:
                p = Pattern(raw); m = p.match(val)
                if m: det.add(p, m if m is not True else None)

        for cname, raw in (tech.get("cookies") or {}).items():
            val = pd.cookies.get(cname.strip())
            if val is not None:
                p = Pattern(raw)
                if not p.string:
                    det.confidence = min(100, det.confidence + p.confidence)
                else:
                    m = p.match(val)
                    if m: det.add(p, m if m is not True else None)

        for raw in _ensure_list(tech.get("html", [])):
            p = Pattern(raw); m = p.match(pd.html)
            if m: det.add(p, m if m is not True else None)

        for raw in _ensure_list(tech.get("scripts", [])) + _ensure_list(tech.get("scriptSrc", [])):
            p = Pattern(raw)
            for src in pd.scripts:
                m = p.match(src)
                if m: det.add(p, m if m is not True else None); break

        meta = tech.get("meta")
        if isinstance(meta, dict):
            for mname, raw in meta.items():
                val = pd.meta.get(mname.lower())
                if val is not None:
                    p = Pattern(raw); m = p.match(val)
                    if m: det.add(p, m if m is not True else None)
        elif isinstance(meta, str):
            val = pd.meta.get("generator")
            if val:
                p = Pattern(meta); m = p.match(val)
                if m: det.add(p, m if m is not True else None)

        for var_path, raw in (tech.get("js") or {}).items():
            val = pd.js.get(var_path)
            if val is not None:
                p = Pattern(raw)
                if not p.string:
                    det.confidence = min(100, det.confidence + p.confidence)
                else:
                    m = p.match(str(val))
                    if m: det.add(p, m if m is not True else None)

        if tech.get("dom"):
            self._check_dom(tech["dom"], pd, det)

        for raw in _ensure_list(tech.get("css", [])):
            if raw.split("\\;")[0] in pd.css_matches:
                det.add(Pattern(raw))

        for raw in _ensure_list(tech.get("text", [])):
            p = Pattern(raw); m = p.match(pd.text)
            if m: det.add(p, m if m is not True else None)

        for raw in _ensure_list(tech.get("xhr", [])):
            p = Pattern(raw)
            for xu in pd.xhr_urls:
                m = p.match(xu)
                if m: det.add(p, m if m is not True else None); break

        for rtype, patterns in (tech.get("dns") or {}).items():
            for raw in _ensure_list(patterns):
                p = Pattern(raw)
                for record in pd.dns.get(rtype, []):
                    m = p.match(record)
                    if m: det.add(p, m if m is not True else None); break

        for raw in _ensure_list(tech.get("certIssuer", [])):
            if pd.cert_issuer:
                p = Pattern(raw); m = p.match(pd.cert_issuer)
                if m: det.add(p, m if m is not True else None)

        return det

    def _check_dom(self, dom, pd, det):
        items = [dom] if isinstance(dom, (dict, str)) else dom
        for item in items:
            if isinstance(item, str):
                for s in item.split(","):
                    if s.strip() and pd.dom.get(s.strip()):
                        det.confidence = min(100, det.confidence + 100); break
            elif isinstance(item, dict):
                for sel, cond in item.items():
                    els = pd.dom.get(sel, [])
                    if not els: continue
                    if not cond:
                        det.confidence = min(100, det.confidence + 100); continue
                    if isinstance(cond, dict):
                        for el in els:
                            if self._match_dom_el(el, cond, det): break

    def _match_dom_el(self, el, cond, det):
        el_a, el_t, el_p = el.get("attributes", {}), el.get("text", ""), el.get("properties", {})
        for aname, raw in cond.get("attributes", {}).items():
            aval = el_a.get(aname)
            if aval is None: return False
            p = Pattern(raw)
            if p.string:
                m = p.match(aval)
                if not m: return False
                det.add(p, m if m is not True else None)
            else:
                det.confidence = min(100, det.confidence + p.confidence)
        tp = cond.get("text")
        if tp:
            p = Pattern(tp); m = p.match(el_t)
            if not m: return False
            det.add(p, m if m is not True else None)
        for pn, raw in cond.get("properties", {}).items():
            pv = el_p.get(pn)
            if pv is None: return False
            p = Pattern(raw)
            if p.string:
                m = p.match(pv)
                if not m: return False
                det.add(p, m if m is not True else None)
        det.confidence = min(100, det.confidence + 100)
        return True

    def _resolve_implies(self, detected):
        changed = True
        while changed:
            changed = False
            for name in list(detected):
                tech = self.technologies.get(name, {})
                for implied in _ensure_list(tech.get("implies", [])):
                    parts = implied.split("\\;")
                    iname, conf = parts[0], 100
                    for part in parts[1:]:
                        kv = part.split(":", 1)
                        if len(kv) == 2 and kv[0] == "confidence":
                            try: conf = int(kv[1])
                            except ValueError: pass
                    if conf >= 50 and iname not in detected and iname in self.technologies:
                        detected[iname] = {"versions": [], "categories": self._get_categories(self.technologies[iname]), "confidence": conf}
                        changed = True

    def _resolve_requires(self, detected):
        remove = []
        for name in detected:
            tech = self.technologies.get(name, {})
            reqs = _ensure_list(tech.get("requires", []))
            if reqs and not any(r in detected for r in reqs):
                remove.append(name); continue
            req_cats = _ensure_list(tech.get("requiresCategory", []))
            if req_cats:
                cat_ids = set()
                for on in detected:
                    if on != name: cat_ids.update(self.technologies.get(on, {}).get("cats", []))
                if not any(int(rc) in cat_ids for rc in req_cats):
                    remove.append(name)
        for n in remove: detected.pop(n, None)

    def _resolve_excludes(self, detected):
        remove = set()
        for name in detected:
            for exc in _ensure_list(self.technologies.get(name, {}).get("excludes", [])):
                if exc in detected: remove.add(exc)
        for n in remove: detected.pop(n, None)


# -- JS snippets for Playwright --

_JS = """(paths)=>{const r={};for(const p of paths){try{const s=p.split('.');let o=window;for(const k of s){if(o==null)break;o=o[k]}if(o!==undefined&&o!==null)r[p]=typeof o==='object'?'true':String(o)}catch(e){}}return r}"""
_DOM = """(sels)=>{const r={};for(const s of sels){try{const e=document.querySelectorAll(s);if(e.length)r[s]=Array.from(e).slice(0,10).map(el=>{const a={};for(const at of el.attributes)a[at.name]=at.value;return{attributes:a,text:(el.textContent||'').substring(0,500),properties:{}}})}catch(e){}}return r}"""
_CSS = """(sels)=>{const m=[];for(const s of sels){try{if(document.querySelector(s))m.push(s)}catch(e){}}return m}"""
_META = """()=>{const m={};document.querySelectorAll('meta[name][content]').forEach(e=>m[e.getAttribute('name').toLowerCase()]=e.getAttribute('content'));document.querySelectorAll('meta[property][content]').forEach(e=>m[e.getAttribute('property').toLowerCase()]=e.getAttribute('content'));return m}"""
_SCRIPTS = """()=>Array.from(document.querySelectorAll('script[src]')).map(s=>s.src||s.getAttribute('src')||'')"""


def _get_cert_issuer(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5); s.connect((hostname, 443))
            for fs in s.getpeercert().get("issuer", []):
                for k, v in fs:
                    if k == "organizationName": return v
    except Exception: pass
    return ""

def _get_dns_records(hostname):
    records = {}
    try:
        import dns.resolver
        for rtype in ("CNAME", "SOA", "MX", "TXT", "NS", "A", "AAAA"):
            try: records[rtype] = [str(r) for r in dns.resolver.resolve(hostname, rtype)]
            except Exception: pass
    except ImportError: pass
    return records

def _eval_batched(page, js_fn, items, chunk=500):
    result = {}
    for i in range(0, len(items), chunk):
        try: result.update(page.evaluate(js_fn, items[i:i+chunk]))
        except Exception: pass
    return result

def collect_playwright(url, engine):
    from playwright.sync_api import sync_playwright
    pd = PageData(url=url)
    xhr_urls = []

    with sync_playwright() as pw:
        for channel in ("chrome", "chromium", "msedge"):
            try:
                browser = pw.chromium.launch(headless=True, channel=channel)
                break
            except Exception:
                continue
        else:
            browser = pw.chromium.launch(headless=True)

        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        page.on("response", lambda r: xhr_urls.append(r.request.url) if r.request.resource_type in ("xhr", "fetch") else None)

        try: response = page.goto(url, wait_until="networkidle", timeout=30000)
        except Exception:
            try: response = page.goto(url, wait_until="domcontentloaded", timeout=30000)
            except Exception as e: browser.close(); raise RuntimeError(f"Failed to load {url}: {e}")

        if response:
            pd.headers = {k.lower(): v for k, v in response.headers.items()}
            pd.url = page.url
        pd.cookies = {c["name"]: c["value"] for c in ctx.cookies()}
        pd.html = page.content()
        pd.scripts = page.evaluate(_SCRIPTS)
        pd.meta = page.evaluate(_META)
        pd.js = _eval_batched(page, _JS, engine.get_js_paths())
        pd.dom = _eval_batched(page, _DOM, engine.get_dom_selectors())
        css = engine.get_css_selectors()
        if css:
            for i in range(0, len(css), 500):
                try: pd.css_matches.update(page.evaluate(_CSS, css[i:i+500]))
                except Exception: pass
        try: pd.text = page.evaluate("()=>document.body?document.body.innerText.substring(0,50000):''")
        except Exception: pd.text = ""
        pd.xhr_urls = xhr_urls
        browser.close()

    host = urlparse(pd.url).hostname or ""
    pd.cert_issuer = _get_cert_issuer(host)
    pd.dns = _get_dns_records(host)
    return pd


def collect_requests(url):
    import requests as req
    from bs4 import BeautifulSoup
    pd = PageData(url=url)
    if "." in url and "http" not in url:
        try: url = req.head("http://" + url, allow_redirects=True, timeout=10).url
        except Exception: url = "http://" + url
    resp = req.get(url, verify=False, timeout=15)
    pd.url, pd.html = resp.url, resp.text
    pd.headers = {k.lower(): v for k, v in resp.headers.items()}
    pd.cookies = resp.cookies.get_dict()
    soup = BeautifulSoup(pd.html, "html.parser")
    pd.scripts = [s.get("src", "") for s in soup.find_all("script", src=True)]
    pd.meta = {m.get("name", "").lower(): m.get("content", "") for m in soup.find_all("meta", attrs={"name": True, "content": True})}
    pd.meta.update({m.get("property", "").lower(): m.get("content", "") for m in soup.find_all("meta", attrs={"property": True, "content": True})})
    host = urlparse(pd.url).hostname or ""
    pd.cert_issuer = _get_cert_issuer(host)
    pd.dns = _get_dns_records(host)
    return pd


def update_db():
    import requests as req
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp_dir = tempfile.mkdtemp()
    try:
        sys.stdout.write(f"  {Fore.CYAN}[~] Downloading categories...{Style.RESET_ALL}"); sys.stdout.flush()
        r = req.get(f"{TECH_BASE_URL}/categories.json", timeout=30); r.raise_for_status()
        categories = r.json(); print(f" {Fore.GREEN}OK{Style.RESET_ALL}")
        technologies = {}
        for letter in "_abcdefghijklmnopqrstuvwxyz":
            sys.stdout.write(f"\r  {Fore.CYAN}[~] Downloading technologies:{Style.RESET_ALL} {letter}.json  "); sys.stdout.flush()
            r = req.get(f"{TECH_BASE_URL}/technologies/{letter}.json", timeout=30); r.raise_for_status()
            technologies.update(r.json())
        print(f"\r  {Fore.GREEN}{Style.BRIGHT}[✓]{Style.RESET_ALL} Downloaded {Fore.WHITE}{Style.BRIGHT}{len(technologies)}{Style.RESET_ALL} technologies" + " " * 20)
        tmp = os.path.join(tmp_dir, "technologies.json")
        with open(tmp, "w") as f: json.dump({"categories": categories, "technologies": technologies}, f)
        shutil.move(tmp, TECHNOLOGIES_FILE)
        print(f"  {Fore.GREEN}{Style.BRIGHT}[✓] Database updated!{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"\n  {Fore.RED}{Style.BRIGHT}[✗] Update failed: {e}{Style.RESET_ALL}"); sys.exit(1)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def print_results(url, results, writefile):
    host = (urlparse(url).hostname or url).upper()
    if not results:
        print(f"\n  {Fore.YELLOW}[!] No technologies detected for {url}{Style.RESET_ALL}\n")
        return

    # group by category
    by_cat = {}
    for name, info in results.items():
        cat = info["categories"][0] if info["categories"] else "Other"
        by_cat.setdefault(cat, []).append((name, info))
    for cat in by_cat:
        by_cat[cat].sort(key=lambda x: x[0].lower())

    print(f"\n  {_hline()}")
    print(f"  {Fore.GREEN}{Style.BRIGHT}  TARGET  {Style.RESET_ALL} {Fore.WHITE}{url}{Style.RESET_ALL}")
    print(f"  {_hline()}\n")

    for cat in sorted(by_cat):
        print(f"  {Fore.CYAN}{Style.BRIGHT}[{cat}]{Style.RESET_ALL}")
        for name, info in by_cat[cat]:
            ver = info["versions"][0] if info["versions"] else None
            conf = info.get("confidence", 100)
            ver_str = f" {Fore.YELLOW}{ver}{Style.RESET_ALL}" if ver else ""
            conf_str = f" {Fore.MAGENTA}({conf}%){Style.RESET_ALL}" if conf < 100 else ""
            print(f"    {Fore.GREEN}•{Style.RESET_ALL} {Style.BRIGHT}{name}{Style.RESET_ALL}{ver_str}{conf_str}")
        print()

    total = len(results)
    cats = len(by_cat)
    print(f"  {_hline()}")
    print(f"  {Fore.WHITE}{Style.BRIGHT}  {total} technologies{Style.RESET_ALL} detected across {cats} categories")
    print(f"  {_hline()}\n")

    # save as JSON
    if writefile:
        json_out = {
            "url": url,
            "scan_time": datetime.now().isoformat(),
            "total": total,
            "technologies": {}
        }
        for name, info in sorted(results.items()):
            json_out["technologies"][name] = {
                "version": info["versions"][0] if info["versions"] else None,
                "confidence": info.get("confidence", 100),
                "categories": info["categories"],
            }
        mode = "r+" if os.path.exists(writefile) else "w"
        existing = []
        if mode == "r+":
            try:
                with open(writefile) as f:
                    existing = json.load(f)
                    if not isinstance(existing, list):
                        existing = [existing]
            except Exception:
                existing = []
        existing.append(json_out)
        with open(writefile, "w") as f:
            json.dump(existing if len(existing) > 1 else existing[0], f, indent=2, ensure_ascii=False)
        print(f"  {Fore.GREEN}[+] Results saved to {writefile}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(description="Wapper - Web Technology Scanner")
    parser.add_argument("-u", "--url", help="URL to analyze")
    parser.add_argument("-f", "--file", default="", help="File with list of URLs")
    parser.add_argument("-wf", "--writefile", default="", help="Save results to JSON file")
    parser.add_argument("--update", action="store_true", help="Update technologies database")
    parser.add_argument("--no-browser", action="store_true", help="Skip headless browser (less detection)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Hide banner")
    args = parser.parse_args()

    if not args.quiet:
        print(_BANNER)

    if args.update:
        update_db()
        if not args.url and not args.file: return

    if not os.path.exists(TECHNOLOGIES_FILE):
        print(f"  {Fore.YELLOW}[*] No database found, downloading...{Style.RESET_ALL}")
        update_db()

    use_pw = not args.no_browser
    if use_pw:
        try: import playwright.sync_api
        except ImportError:
            print(f"  {Fore.YELLOW}[!] Playwright not installed, using HTTP-only mode.{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}    Install: pip install playwright && playwright install chromium{Style.RESET_ALL}\n")
            use_pw = False

    engine = WappalyzerEngine(TECHNOLOGIES_FILE)
    mode = f"{Fore.GREEN}browser{Style.RESET_ALL}" if use_pw else f"{Fore.YELLOW}HTTP-only{Style.RESET_ALL}"

    def scan(url):
        print(f"  {Fore.CYAN}[~] Scanning{Style.RESET_ALL} {Fore.WHITE}{url}{Style.RESET_ALL} [{mode}]", end="", flush=True)
        try:
            pd = collect_playwright(url, engine) if use_pw else collect_requests(url)
        except Exception as e:
            print(f"\r  {Fore.RED}{Style.BRIGHT}[✗] Error:{Style.RESET_ALL} {url}: {e}")
            return
        results = engine.analyze(pd)
        print(f"\r  {Fore.GREEN}{Style.BRIGHT}[✓] Scanned{Style.RESET_ALL} {Fore.WHITE}{url}{Style.RESET_ALL} — {len(results)} technologies found" + " " * 20)
        print_results(pd.url, results, args.writefile)

    if args.file:
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip()]
        print(f"  {Fore.WHITE}{Style.BRIGHT}Loaded {len(urls)} targets{Style.RESET_ALL}\n")
        for i, url in enumerate(urls, 1):
            print(f"  {Fore.CYAN}[{i}/{len(urls)}]{Style.RESET_ALL}", end=" ")
            scan(url)
    if args.url: scan(args.url)
    if not args.url and not args.file and not args.update: parser.print_help()

if __name__ == "__main__":
    main()
