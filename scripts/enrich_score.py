#!/usr/bin/env python3
"""
enrich_score.py — Aggressive Prioritizer (Noise-Hardened)

Usage:
  python3 scripts/enrich_score.py candidates.txt --top 300 --cap 1500 --workers 35 --timeout 4

Outputs:
  tmp/enrich/all.json      (all scored, with noise still visible)
  tmp/enrich/top.json      (sorted + noise nuked)
  tmp/enrich/top_hosts.txt (clean, high-value only)

Purpose:
  Prioritize hosts most likely to yield medium/high/critical bounty payouts.
  Strongly penalize/no-drop SaaS/vendor/userstore garbage (Shopify, Zendesk, etc).
"""

import sys, json, ssl, socket, argparse, time, os, re
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from dateutil import parser as dtparser
    import dns.resolver
    import requests
except Exception:
    print("[!] Install deps: pip3 install python-dateutil dnspython requests", file=sys.stderr)
    sys.exit(2)

# ---------------- Args ----------------
parser = argparse.ArgumentParser()
parser.add_argument("infile", help="candidates file (one host per line)")
parser.add_argument("--top", type=int, default=300, help="how many top hosts to output")
parser.add_argument("--cap", type=int, default=1500, help="process at most N candidates")
parser.add_argument("--workers", type=int, default=35, help="concurrent workers")
parser.add_argument("--timeout", type=int, default=4, help="timeout for http/dns/ssl")
parser.add_argument("--debug", action="store_true", help="verbose logs")
args = parser.parse_args()

INP, TOP_N, CAP, WORKERS, TIMEOUT, DEBUG = (
    args.infile, args.top, args.cap, args.workers, args.timeout, args.debug
)

with open(INP) as fh:
    hosts_all = [l.strip() for l in fh if l.strip()]
hosts = hosts_all[:CAP]

# ---------------- Tunables ----------------
sslctx = ssl.create_default_context()
resolver = dns.resolver.Resolver()
resolver.lifetime = TIMEOUT
resolver.timeout = TIMEOUT

UA = "Mozilla/5.0 (compatible; ReconBot/2.0; +https://example.com/)"
session = requests.Session()
session.headers.update({"User-Agent": UA})
adapter = requests.adapters.HTTPAdapter(pool_connections=WORKERS, pool_maxsize=WORKERS, max_retries=1)
session.mount("http://", adapter)
session.mount("https://", adapter)

# ---------------- Strong signals ----------------
PROVIDERS = [
    "s3.amazonaws.com","netlify.app","vercel.app","github.io",
    "cloudfront.net","azureedge.net","storage.googleapis.com"
]

HIGH_VALUE_PATHS = [
    "/admin","/login","/signin","/dashboard","/wp-admin","/manager",
    "/.git/","/.env","/config.json","/backup.zip","/backup.tar.gz",
    "/api/graphql","/graphql"
]

ADMIN_HINTS = ["admin","dashboard","login","signin","console","wp-admin","management","portal"]
SUSPICIOUS_STRINGS = ["db_password","db_username",".env","backup","password","aws_access_key_id","private key"]

# ---------------- Blacklists ----------------
BLACKLIST_PATTERNS = [
    r"\.slack\.com$", r"\.herokuapp\.com$", r"\.githubusercontent\.com$",
    r"^dev-|^staging-|^test-", r"-dev$|-staging$|-test$",
    r"\.myshopify\.com$", r"\.wordpress\.com$", r"\.zendesk\.com$",
    r"\.atlassian\.net$", r"\.cloudflarepages\.com$", r"\.freshdesk\.com$",
    r"\.salesforce\.com$"
]
BLACKLIST_RE = [re.compile(p, re.I) for p in BLACKLIST_PATTERNS]

# ---------------- Scoring Weights ----------------
WEIGHTS = {
    "cname_provider": 40,
    "cors_wildcard": 35,
    "admin_path": 30,
    "exposed_file": 28,
    "recent_cert": 20,
    "http_live": 12,
    "robots_admin": 12,
    "title_admin_hint": 10,
    "blacklist_penalty": -50,   # cranked up
    "vendor_penalty": -50       # cranked up
}

# ---------------- Helpers ----------------
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
        pass
    addrs = []
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
            return {"status": r.status_code, "scheme": scheme}
        except Exception:
            continue
    return {"status": None, "scheme": "https://"}

def robots_has_admin(host, scheme):
    try:
        r = session.get(f"{scheme}{host}/robots.txt", timeout=TIMEOUT)
        if r.status_code == 200:
            low = r.text.lower()
            return any(h in low for h in ADMIN_HINTS)
    except Exception:
        pass
    return False

def cors_wildcard(host, scheme):
    try:
        r = session.options(f"{scheme}{host}", timeout=TIMEOUT)
        return r.headers.get("Access-Control-Allow-Origin") == "*"
    except Exception:
        return False

def quick_probe(host, scheme):
    signals = []
    for p in HIGH_VALUE_PATHS:
        try:
            r = session.get(f"{scheme}{host}{p}", timeout=TIMEOUT, allow_redirects=True)
            if r.status_code in (200,301,302):
                low = (r.text or "").lower()
                if any(h in low for h in ADMIN_HINTS):
                    signals.append({"type":"admin_hint","path":p})
                if any(k in p for k in [".git",".env","backup","config"]):
                    signals.append({"type":"exposed_file","path":p})
                if any(s in low for s in SUSPICIOUS_STRINGS):
                    signals.append({"type":"sensitive_content","path":p})
        except Exception:
            continue
    return signals

# ---------------- Scoring ----------------
def score_host(h):
    row = {"host": h, "score": 0, "signals": []}

    if is_blacklisted(h):
        row["score"] += WEIGHTS["blacklist_penalty"]
        row["signals"].append({"type":"blacklist"})
        return row

    dns = dns_info(h)
    cname = dns.get("cname")

    if cname and any(p in cname.lower() for p in PROVIDERS):
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

    head = http_head(h)
    status, scheme = head.get("status"), head.get("scheme","https://")
    if status and 200 <= status < 400:
        row["score"] += WEIGHTS["http_live"]
        row["signals"].append({"type":"http_live","status":status})

        if robots_has_admin(h, scheme):
            row["score"] += WEIGHTS["robots_admin"]
            row["signals"].append({"type":"robots_admin"})

        if cors_wildcard(h, scheme):
            row["score"] += WEIGHTS["cors_wildcard"]
            row["signals"].append({"type":"cors_wildcard"})

        for sig in quick_probe(h, scheme):
            if sig["type"] == "admin_hint":
                row["score"] += WEIGHTS["admin_path"]
            elif sig["type"] == "exposed_file":
                row["score"] += WEIGHTS["exposed_file"]
            elif sig["type"] == "sensitive_content":
                row["score"] += int(WEIGHTS["exposed_file"] * 0.8)
            row["signals"].append(sig)

    # vendor penalty after all scoring
    if cname and any(v in cname.lower() for v in ["myshopify.com","wordpress.com","zendesk.com"]):
        row["score"] += WEIGHTS["vendor_penalty"]
        row["signals"].append({"type":"vendor_penalty","value":cname})

    return row

# ---------------- Run ----------------
def run_all(hosts):
    out = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(score_host,h):h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                out.append(fut.result())
            except Exception as e:
                out.append({"host":futures[fut],"score":0,"err":str(e)})
            if i % 20 == 0 and DEBUG:
                print(f"[+] progress: {i}/{len(hosts)}", file=sys.stderr)
    return sorted(out, key=lambda x: x["score"], reverse=True)

out_sorted = run_all(hosts)

os.makedirs("tmp/enrich", exist_ok=True)
with open("tmp/enrich/all.json","w") as f: json.dump(out_sorted, f, indent=2)

filtered = [r for r in out_sorted if r["score"] > 0 and not is_blacklisted(r["host"])]
with open("tmp/enrich/top.json","w") as f: json.dump(filtered[:TOP_N], f, indent=2)
with open("tmp/enrich/top_hosts.txt","w") as f:
    for r in filtered[:TOP_N]: f.write(r["host"]+"\n")

print(f"[+] Wrote {len(filtered[:TOP_N])} clean hosts -> tmp/enrich/top_hosts.txt", file=sys.stderr)
