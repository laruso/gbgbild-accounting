"""
Probe HTTPS API — Phase 2.
Reads the root HTML, extracts all JS/CSS links, fetches each JS file,
and searches for API endpoint patterns. This finds the exact URLs the
LFP web UI uses for job accounting data.

Run on the Windows machine: python3 probe_https2.py > probe_https2_log.txt 2>&1
"""
import urllib.request, urllib.error, ssl, sys, io, re, time

if hasattr(sys.stdout, 'buffer'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

PRINTER = "10.0.0.48"
BASE    = f"https://{PRINTER}"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_ciphers("DEFAULT:@SECLEVEL=1")

def fetch(path, method="GET", headers=None):
    url = BASE + path if path.startswith("/") else path
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "EpsonDeviceFramework/1.0")
    req.add_header("Accept", "*/*")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            data = r.read()
            return r.status, dict(r.headers), data
    except urllib.error.HTTPError as e:
        body = b""
        try: body = e.read()
        except: pass
        return e.code, {}, body
    except Exception as e:
        return None, {}, str(e).encode()


print("=" * 70)
print("Probe HTTPS Phase 2 — HTML/JS crawl for API endpoints")
print("=" * 70)

# ── Step 1: Fetch root HTML ────────────────────────────────────────────────────
print("\n=== Step 1: Root page HTML ===")
status, hdrs, body = fetch("/")
html = body.decode('utf-8', errors='replace')
print(f"Status: {status}  Size: {len(body)}")
print(f"Content-Type: {hdrs.get('Content-Type', '?')}")
print("\nFull HTML:")
print(html)
print()

# ── Step 2: Also fetch /PRESENTATION/ and the redirect targets ────────────────
for path in ["/PRESENTATION/", "/PRESENTATION/HTML/TOP/PRNSTS.HTML",
             "/PRESENTATION/HTML/TOP/TOPPAGE.HTML"]:
    status, hdrs, body = fetch(path)
    text = body.decode('utf-8', errors='replace')
    print(f"\n=== {path} (status={status}, {len(body)}B) ===")
    print(text[:2000])

# ── Step 3: Extract all JS/CSS references from the root HTML ──────────────────
print("\n\n=== Step 3: Extracted links / scripts from root HTML ===")
# Find all src= and href= attributes
refs = re.findall(r'(?:src|href|action)\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE)
print(f"Found {len(refs)} references:")
for r in refs:
    print(f"  {r}")

# Also check redirect targets (meta refresh, location.href, window.location)
redirects = re.findall(r'(?:URL=|location\.href|window\.location)\s*[=\'\"]+\s*[\'\"]*([^\'">\s]+)', html, re.IGNORECASE)
print(f"\nRedirects/locations found: {redirects}")

# ── Step 4: Fetch each JS file and search for API patterns ────────────────────
print("\n\n=== Step 4: Fetching JS files and searching for API endpoints ===")

js_refs = [r for r in refs if r.endswith('.js') or '.js?' in r]
# Also look in the redirect targets
all_paths = list(set(refs + redirects + js_refs))

fetched_js = []
for ref in all_paths:
    if not ref.startswith('http') and not ref.startswith('/'):
        ref = '/PRESENTATION/' + ref  # relative path resolution

    if ref.startswith('http') and PRINTER not in ref:
        continue  # external resource, skip

    path = ref if ref.startswith('/') else '/' + ref
    status, hdrs, data = fetch(path)
    ct = hdrs.get('Content-Type', '')

    if status != 200:
        continue

    text = data.decode('utf-8', errors='replace')
    print(f"\n  --- {path} ({len(data)}B, {ct}) ---")

    if 'javascript' in ct or path.endswith('.js'):
        fetched_js.append((path, text))
        # Search for interesting patterns
        api_patterns = re.findall(
            r'["\'](/[a-zA-Z0-9/_\-\.]+(?:job|log|ink|account|print|status|info|data|service)[a-zA-Z0-9/_\-\.]*)["\']',
            text, re.IGNORECASE
        )
        if api_patterns:
            print(f"  API-like paths found:")
            for p in sorted(set(api_patterns)):
                print(f"    {p}")

        # Also find all string literals that look like paths
        paths_found = re.findall(r'["\'](/[A-Z][A-Za-z0-9/_\-\.]+)["\']', text)
        if paths_found:
            print(f"  Other paths found:")
            for p in sorted(set(paths_found))[:30]:
                print(f"    {p}")
    else:
        print(f"  Content preview: {text[:300]}")


# ── Step 5: Walk ALL unique paths we found in JS ──────────────────────────────
print("\n\n=== Step 5: Try all paths found in JS ===")
all_found_paths = set()
for path, js_text in fetched_js:
    found = re.findall(r'["\'](/[A-Za-z0-9/_\-\.]{4,})["\']', js_text)
    all_found_paths.update(found)

print(f"Total unique paths to try: {len(all_found_paths)}")
for p in sorted(all_found_paths):
    status, hdrs, data = fetch(p)
    if status == 200 and len(data) > 200:
        ct = hdrs.get('Content-Type', '')
        text = data.decode('utf-8', errors='replace')
        flag = " *** LARGE ***" if len(data) > 5000 else " [data]"
        print(f"  {status}  {len(data):7d}B  {p:<55s} {ct[:30]}{flag}")
        print(f"    preview: {text[:150].replace(chr(10),' ')}")
    time.sleep(0.1)

# ── Step 6: Try paths with typical Epson JS-loaded URL patterns ───────────────
print("\n\n=== Step 6: Epson AJAX / dynamic endpoint patterns ===")

# Epson printers often use these patterns for their web UI data endpoints
dynamic_paths = [
    # Common Epson firmware web UI patterns
    "/PRESENTATION/HTML/TOP/PRNSTS.HTML",
    "/PRESENTATION/HTML/TOP/INFORMATION.HTML",
    "/PRESENTATION/HTML/TOP/NETWORK.HTML",
    "/PRESENTATION/HTML/TOP/MAINTENANCE.HTML",
    "/PRESENTATION/EPSONCONNECT/",
    "/PRESENTATION/ADVANCED/",
    "/PRESENTATION/ADVANCE/",
    # Data endpoints often served without .html
    "/PRESENTATION/data/",
    "/PRESENTATION/job/",
    "/PRESENTATION/jobs/",
    "/PRESENTATION/log/",
    "/PRESENTATION/ink/",
    "/PRESENTATION/status/",
    # Epson uses uppercase paths
    "/PRESENTATION/HTML/STSPRN/",
    "/PRESENTATION/HTML/JOBLOG/",
    "/PRESENTATION/HTML/INKINFO/",
    "/PRESENTATION/HTML/ACCOUNT/",
    "/PRESENTATION/HTML/MNTCNT/",
    "/PRESENTATION/HTML/USAGELOG/",
    "/PRESENTATION/HTML/PRINTLOG/",
    "/PRESENTATION/HTML/JOBLIST/",
    "/PRESENTATION/HTML/JOBINFO/",
    # Try deeper paths
    "/PRESENTATION/HTML/TOP/JOBLOG.HTML",
    "/PRESENTATION/HTML/TOP/JOBINFO.HTML",
    "/PRESENTATION/HTML/TOP/INKINFO.HTML",
    "/PRESENTATION/HTML/TOP/USAGELOG.HTML",
    "/PRESENTATION/HTML/TOP/PRINTLOG.HTML",
    "/PRESENTATION/HTML/TOP/ACCOUNT.HTML",
    "/PRESENTATION/HTML/TOP/COUNTER.HTML",
    "/PRESENTATION/HTML/TOP/USAGE.HTML",
    # Data files
    "/PRESENTATION/HTML/TOP/PRNSTS.XML",
    "/PRESENTATION/HTML/TOP/STATUS.XML",
    "/PRESENTATION/HTML/TOP/INKSTS.XML",
    "/PRESENTATION/HTML/TOP/JOBLOG.XML",
    "/PRESENTATION/HTML/TOP/JOBSTS.XML",
    # Epson Remote management paths
    "/WEBCONFIG/",
    "/WEBCONFIG/status",
    "/WEBCONFIG/joblog",
    "/WEBCONFIG/ink",
]

for p in dynamic_paths:
    status, hdrs, data = fetch(p)
    if status in (200, 301, 302):
        ct = hdrs.get('Content-Type', '')
        loc = hdrs.get('Location', '')
        text = data.decode('utf-8', errors='replace') if data else ''
        flag = " *** LARGE ***" if len(data) > 5000 else (" [data]" if len(data) > 200 else "")
        print(f"  {status}  {len(data):7d}B  {p:<55s} {ct[:20]}{flag}")
        if loc: print(f"    → Location: {loc}")
        if flag and text: print(f"    preview: {text[:150].replace(chr(10),' ')}")
    time.sleep(0.1)

print("\n\n=== Done ===")
