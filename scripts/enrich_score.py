#!/usr/bin/env python3
# scripts/enrich_score.py
# Usage: python3 scripts/enrich_score.py candidates.txt --top 300 --cap 1500 --workers 50
# Outputs: tmp/enrich/all.json, tmp/enrich/top.json, tmp/enrich/top_hosts.txt

import sys, json, ssl, socket, argparse, time, os
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
parser.add_argument("--workers", type=int, default=50, help="concurrent workers (tune down if runners block)")
parser.add_argument("--timeout", type=int, default=4, help="http/dns/ssl timeout seconds")
args = parser.parse_args()

INP = args.infile
TOP_N = args.top
CAP = args.cap
WORKERS = args.workers
TIMEOUT = args.timeout

with open(INP) as fh:
    hosts_all = [l.strip() for l in fh if l.strip()]
hosts = hosts_all[:CAP]

sslctx = ssl.create_default_context()
PROVIDERS = [
    "s3.amazonaws.com","netlify.app","vercel.app","github.io",
    "cloudfront.net","azureedge.net","storage.googleapis.com",
]
ADMIN_HINTS = ["admin","/admin","/dashboard","/wp-admin","console","signin","login"]

# shared DNS resolver instance (thread-safe enough for our usage)
resolver = dns.resolver.Resolver()
resolver.lifetime = TIMEOUT
resolver.timeout = TIMEOUT

UA = "Mozilla/5.0 (compatible; ReconBot/1.0; +https://example.com/)"

session = requests.Session()
session.headers.update({"User-Agent": UA})
adapter = requests.adapters.HTTPAdapter(pool_connections=WORKERS, pool_maxsize=WORKERS, max_retries=1)
session.mount("http://", adapter)
session.mount("https://", adapter)

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

def dns_cname(host):
    try:
        ans = resolver.resolve(host, 'CNAME')
        if ans:
            return str(ans[0].target).rstrip('.')
        return None
    except Exception:
        return None

def http_head(host):
    for scheme in ("https://", "http://"):
        try:
            r = session.head(scheme+host, timeout=TIMEOUT, allow_redirects=True)
            return {"status": r.status_code, "server": r.headers.get("Server",""), "scheme": scheme}
        except Exception:
            continue
    return {"status": None, "server": "", "scheme": "https://"}

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
        v = r.headers.get("Access-Control-Allow-Origin")
        return v == "*"
    except Exception:
        return False

def score_item(h):
    s = 0
    tls = tls_info(h)
    if tls.get("ok") and tls.get("notAfter"):
        try:
            d = dtparser.parse(tls["notAfter"])
            days_left = (d - datetime.now(timezone.utc)).days
            if 0 < days_left < 90:
                s += 30
        except Exception:
            pass
    cname = dns_cname(h)
    if cname and any(p in cname.lower() for p in PROVIDERS):
        s += 20
    head = http_head(h)
    scheme = head.get("scheme", "https://")
    if head.get("status") and 200 <= head["status"] < 400:
        s += 15
        if robots_has_admin(h, scheme):
            s += 12
    if cors_wildcard(h, scheme):
        s += 18
    if cname and any(v in cname.lower() for v in ["myshopify.com", "herokuapp.com"]):
        s -= 15
    return {
        "host": h,
        "score": s,
        "tls_ok": tls.get("ok"),
        "tls_err": tls.get("err") if not tls.get("ok") else None,
        "cname": cname,
        "http_status": head.get("status"),
    }

out = []
start = time.time()
print(f"[+] Running enrichment on {len(hosts)} hosts using {WORKERS} workers (cap={CAP})", file=sys.stderr)
with ThreadPoolExecutor(max_workers=WORKERS) as ex:
    futures = {ex.submit(score_item, h): h for h in hosts}
    completed = 0
    for fut in as_completed(futures):
        completed += 1
        try:
            row = fut.result()
        except Exception as e:
            row = {"host": futures[fut], "score": 0, "err": str(e)}
        out.append(row)
        if completed % 50 == 0:
            print(f"[+] progress: {completed}/{len(hosts)}", file=sys.stderr)

out_sorted = sorted(out, key=lambda x: x.get("score", 0), reverse=True)

os.makedirs("tmp/enrich", exist_ok=True)
with open("tmp/enrich/all.json", "w") as f:
    json.dump(out_sorted, f, indent=2)
with open("tmp/enrich/top.json", "w") as f:
    json.dump(out_sorted[:TOP_N], f, indent=2)
with open("tmp/enrich/top_hosts.txt", "w") as f:
    for r in out_sorted[:TOP_N]:
        f.write(r["host"] + "\n")

elapsed = time.time() - start
print(f"[+] Done. Wrote tmp/enrich/top_hosts.txt ({min(TOP_N,len(out_sorted))} hosts) in {elapsed:.1f}s", file=sys.stderr)
