#!/usr/bin/env python3
# scripts/enrich_score.py (AGGRESSIVE PRIORITIZER)
# Usage: python3 scripts/enrich_score.py candidates.txt --top 300 --cap 1500 --workers 35 --timeout 4
# Outputs: tmp/enrich/all.json, tmp/enrich/top.json, tmp/enrich/top_hosts.txt
# Purpose: focus on hosts most likely to yield medium/high/critical payouts (takeovers, exposed admin, backups, cors *)

import sys, json, ssl, socket, argparse, time, os, re
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# dependencies: python-dateutil dnspython requests
try:
    from dateutil import parser as dtparser
    import dns.resolver
    import requests
except Exception:
    print("[!] Install deps: pip3 install python-dateutil dnspython requests", file=sys.stderr)
    sys.exit(2)

parser = argparse.ArgumentParser()
parser.add_argument("infile", help="candidates file (one host per line)")
parser.add_argument("--top", type=int, default=300, help="how many top hosts to output")
parser.add_argument("--cap", type=int, default=1500, help="process at most N candidates (cap)")
parser.add_argument("--workers", type=int, default=35, help="concurrent workers (tune down if runners block)")
parser.add_argument("--timeout", type=int, default=4, help="http/dns/ssl timeout seconds")
parser.add_argument("--debug", action="store_true", help="more verbose logs")
args = parser.parse_args()

INP = args.infile
TOP_N = args.top
CAP = args.cap
WORKERS = args.workers
TIMEOUT = args.timeout
DEBUG = args.debug

with open(INP) as fh:
    hosts_all = [l.strip() for l in fh if l.strip()]
hosts = hosts_all[:CAP]

# Tunables (adjust if you know your runner/limits)
sslctx = ssl.create_default_context()
resolver = dns.resolver.Resolver()
resolver.lifetime = TIMEOUT
resolver.timeout = TIMEOUT

UA = "Mozilla/5.0 (compatible; ReconBot/1.0; +https://example.com/)"
session = requests.Session()
session.headers.update({"User-Agent": UA})
adapter = requests.adapters.HTTPAdapter(pool_connections=WORKERS, pool_maxsize=WORKERS, max_retries=1)
session.mount("http://", adapter)
session.mount("https://", adapter)

# Provider takeover indicators (strong)
PROVIDERS = [
    "s3.amazonaws.com","netlify.app","vercel.app","github.io",
    "cloudfront.net","azureedge.net","storage.googleapis.com",
]

# Blacklist (high-noise hosts to remove)
BLACKLIST_PATTERNS = [
    r"\.slack\.com$",
    r"\.herokuapp\.com$",
    r"\.githubusercontent\.com$",
    r"^dev-|^staging-|-staging$|-dev$|-test$",
    r"^test-",
]

BLACKLIST_RE = [re.compile(p, re.I) for p in BLACKLIST_PATTERNS]

# quick high-value paths to probe if host is live
HIGH_VALUE_PATHS = [
    "/admin","/admin/","/dashboard","/dashboard/","/login","/signin","/wp-admin","/manager",
    "/.git/","/.env","/config.json","/backup.zip","/backup.tar.gz","/api/graphql","/graphql"
]

ADMIN_HINTS = ["admin","dashboard","login","signin","console","wp-login","wp-admin","management","portal"]
SUSPICIOUS_PAYLOAD_STRINGS = ["DB_PASSWORD","DB_USERNAME",".env","backup","password","aws_access_key_id","PRIVATE KEY"]

# scoring weights (big wins for takeover & exposure)
WEIGHTS = {
    "cname_provider": 40,
    "cors_wildcard": 35,
    "admin_path": 30,
    "exposed_file": 28,
    "recent_cert": 20,
    "http_live": 12,
    "robots_admin": 12,
    "title_admin_hint": 10,
    "wayback_evidence": 15,  # not used by default
    "blacklist_penalty": -40,
    "vendor_penalty": -12
}

def is_blacklisted(h):
    for rx in BLACKLIST_RE:
        if rx.search(h):
            return True
    return False

def tls_info(host):
    try:
        s = sslctx.wrap_socket(socket.socket(), server_hostname=host)
        s.settimeout(TIMEOUT)
        s.connect((host, 443))
        cert = s.getpeercert()
        s.close()
        return {"ok": True, "notAfter": cert.get("notAfter")}
    except Exception as e:
        return {"ok": False, "err": str(e)}

def dns_info(host):
    cname = None
    try:
        ans = resolver.resolve(host, 'CNAME')
        if ans:
            cname = str(ans[0].target).rstrip('.')
    except Exception:
        cname = None
    # A/AAAA resolution
    addrs=[]
    try:
        r = resolver.resolve(host, 'A')
        addrs = [str(x) for x in r]
    except Exception:
        pass
    return {"cname": cname, "addrs": addrs}

def http_head(host):
    for scheme in ("https://", "http://"):
        try:
            r = session.head(scheme+host, timeout=TIMEOUT, allow_redirects=True)
            return {"status": r.status_code, "server": r.headers.get("Server",""), "scheme": scheme, "title": ""}
        except Exception:
            continue
    return {"status": None, "server": "", "scheme": "https://"}

def robots_has_admin(host, scheme):
    try:
        r = session.get(f"{scheme}{host}/robots.txt", timeout=TIMEOUT)
        if r.status_code == 200:
            low = r.text.lower()
            for hint in ADMIN_HINTS:
                if hint in low:
                    return True, r.text[:400]
    except Exception:
        pass
    return False, None

def cors_wildcard(host, scheme):
    try:
        r = session.options(f"{scheme}{host}", timeout=TIMEOUT)
        v = r.headers.get("Access-Control-Allow-Origin")
        return v == "*", r.headers if r is not None else {}
    except Exception:
        return False, {}

def quick_path_probe(host, scheme):
    """Small set of GETs to detect admin pages / exposed files. Returns signals list."""
    signals = []
    for p in HIGH_VALUE_PATHS:
        url = f"{scheme}{host}{p}"
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code in (200,301,302):
                text = (r.text or "")[:2048]
                low = text.lower()
                # admin/login hint by page text or title
                if any(h in low for h in ADMIN_HINTS):
                    signals.append({"path":p,"type":"admin_hint","status":r.status_code})
                # exposed .git or .env or backup by URL or content
                if ".git" in p or ".env" in p or "backup" in p or "config" in p:
                    signals.append({"path":p,"type":"exposed_file","status":r.status_code})
                # quick scan for suspicious strings
                if any(s.lower() in low for s in SUSPICIOUS_PAYLOAD_STRINGS):
                    signals.append({"path":p,"type":"sensitive_content","status":r.status_code})
        except Exception:
            continue
    return signals

def score_host(h):
    # base
    row = {"host": h, "score": 0, "signals": []}
    # blacklist check first
    if is_blacklisted(h):
        row["score"] += WEIGHTS["blacklist_penalty"]
        row["signals"].append({"type":"blacklist","note":"blacklist pattern matched"})
        return row

    # DNS / TLS quick
    dns = dns_info(h)
    cname = dns.get("cname")
    if cname:
        row["signals"].append({"type":"cname","value":cname})
        if any(p in cname.lower() for p in PROVIDERS):
            row["score"] += WEIGHTS["cname_provider"]
            row["signals"].append({"type":"cname_provider","value":cname})

    tls = tls_info(h)
    if tls.get("ok") and tls.get("notAfter"):
        try:
            d = dtparser.parse(tls["notAfter"])
            days_left = (d - datetime.now(timezone.utc)).days
            if 0 < days_left < 60:
                row["score"] += WEIGHTS["recent_cert"]
                row["signals"].append({"type":"recent_cert","days_left":days_left})
        except Exception:
            pass
    else:
        # no TLS: small negative but not fatal
        pass

    # HTTP head to see if alive
    head = http_head(h)
    status = head.get("status")
    scheme = head.get("scheme","https://")
    if status and 200 <= status < 400:
        row["score"] += WEIGHTS["http_live"]
        row["signals"].append({"type":"http_live","status":status})
        # title check cheap: do a small GET for root to capture title if needed
        try:
            r = session.get(f"{scheme}{h}", timeout=TIMEOUT, allow_redirects=True)
            title = ""
            m = re.search(r"<title[^>]*>([^<]+)</title>", (r.text or ""), re.I)
            if m:
                title = m.group(1).strip()
                if any(x in title.lower() for x in ADMIN_HINTS):
                    row["score"] += WEIGHTS["title_admin_hint"]
                    row["signals"].append({"type":"title_admin","title":title})
        except Exception:
            pass

        # robots
        robots_ok, robots_snip = robots_has_admin(h, scheme)
        if robots_ok:
            row["score"] += WEIGHTS["robots_admin"]
            row["signals"].append({"type":"robots_admin","snippet":(robots_snip or "")[:300]})

        # CORS wildcard
        cors_ok, cors_hdrs = cors_wildcard(h, scheme)
        if cors_ok:
            row["score"] += WEIGHTS["cors_wildcard"]
            row["signals"].append({"type":"cors_wildcard","headers":dict(cors_hdrs)})

        # quick path probes (small)
        probes = quick_path_probe(h, scheme)
        for p in probes:
            if p["type"] == "admin_hint":
                row["score"] += WEIGHTS["admin_path"]
                row["signals"].append(p)
            elif p["type"] == "exposed_file":
                row["score"] += WEIGHTS["exposed_file"]
                row["signals"].append(p)
            elif p["type"] == "sensitive_content":
                row["score"] += int(WEIGHTS["exposed_file"] * 0.8)
                row["signals"].append(p)
    else:
        # not live: if cname provider exists, still keep some score (possible takeover)
        if cname and any(p in cname.lower() for p in PROVIDERS):
            row["score"] += int(WEIGHTS["cname_provider"] * 0.6)
            row["signals"].append({"type":"cname_provider_offline","value":cname})

    # vendor penalty for pure vendor hostnames (no corroboration)
    if cname and any(v in cname.lower() for v in ["myshopify.com"]):
        row["score"] += WEIGHTS["vendor_penalty"]
        row["signals"].append({"type":"vendor_penalty","value":cname})

    # attach DNS/TLS/http summary
    row.update({
        "cname": cname,
        "addrs": dns.get("addrs",[]),
        "tls_ok": tls.get("ok"),
        "tls_err": tls.get("err") if not tls.get("ok") else None,
        "http_status": status
    })

    return row

def run_all(hosts):
    out=[]
    start = time.time()
    if DEBUG:
        print(f"[+] DEBUG: starting enrichment for {len(hosts)} hosts with {WORKERS} workers", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(score_host,h):h for h in hosts}
        completed=0
        for fut in as_completed(futures):
            completed+=1
            try:
                row = fut.result()
            except Exception as e:
                row = {"host":futures[fut],"score":0,"err":str(e)}
            out.append(row)
            if completed % 20 == 0 or DEBUG:
                print(f"[+] progress: {completed}/{len(hosts)}", file=sys.stderr)
    elapsed = time.time()-start
    if DEBUG:
        print(f"[+] enrichment finished in {elapsed:.1f}s", file=sys.stderr)
    return sorted(out, key=lambda x: x.get("score",0), reverse=True)

# run
out_sorted = run_all(hosts)
os.makedirs("tmp/enrich", exist_ok=True)
with open("tmp/enrich/all.json","w") as f:
    json.dump(out_sorted, f, indent=2)
with open("tmp/enrich/top.json","w") as f:
    json.dump(out_sorted[:TOP_N], f, indent=2)
with open("tmp/enrich/top_hosts.txt","w") as f:
    for r in out_sorted[:TOP_N]:
        f.write(r["host"]+"\n")

print(f"[+] Wrote tmp/enrich/top_hosts.txt ({min(TOP_N,len(out_sorted))} hosts)", file=sys.stderr)
