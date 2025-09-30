from flask import Flask, request, jsonify, abort
import requests
import tldextract
import subprocess
import os
import hmac

WHITELIST_PATH = r"C:\Squid\etc\squid\whitelist.txt"
SQUID_BIN = r"C:\Squid\bin\squid.exe"
PYTHON_VVER = os.getenv("PYTHON_VVER") #1.246.43
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5566
REQUEST_TIMEOUT = 15
MAX_REDIRECTS = 10
VERIFY_SSL = False

from flask_cors import CORS
app = Flask(__name__)
CORS(app)

def version(ver):
    return hmac.compare_digest(ver or "", PYTHON_VVER)

def normal_from_url(url):
    try:
        te = tldextract.extract(url)
        if te.domain:
            domain = te.domain + (("." + te.suffix) if te.suffix else "")
            return domain.lower()
    except Exception:
        return None
    return None

def add_domains_to_whitelist(domains):
    # read existing lines
    if not os.path.exists(WHITELIST_PATH):
        os.makedirs(os.path.dirname(WHITELIST_PATH), exist_ok=True)
        open(WHITELIST_PATH, "w", encoding="utf-8").close()
    with open(WHITELIST_PATH, "r", encoding="utf-8") as f:
        existing = {ln.strip().lower() for ln in f if ln.strip()}
    added = []
    with open(WHITELIST_PATH, "a", encoding="utf-8") as f:
        for d in domains:
            entry = "." + d if not d.startswith(".") else d
            if entry not in existing:
                f.write(entry + "\n")
                existing.add(entry)
                added.append(entry)
    return added

def reload_squid():
    try:
        res = subprocess.run([SQUID_BIN, "-k", "reconfigure"], capture_output=True, text=True, check=True)
        return True, res.stdout.strip()
    except subprocess.CalledProcessError as e:
        return False, (e.stdout + e.stderr)

@app.route("/resolve_redirects", methods=["GET"])
def resolve_redirects():
    vver = request.args.get("vver", "")
    if not version(vver):
        abort(403)
    data = request.args.get("url")
    if not data or "http" not in data:
        return jsonify({"error":"No URL provided"}), 400

    try:
        session = requests.Session()
        resp = session.get(data, allow_redirects=True, timeout=REQUEST_TIMEOUT, verify=VERIFY_SSL)
    except requests.RequestException as ex:
        return jsonify({"error": "request_failed", "details": str(ex)}), 502

    chain_urls = []
    for r in resp.history:
        chain_urls.append(r.url)
    chain_urls.append(resp.url)  # final

    if len(chain_urls) > MAX_REDIRECTS + 1:
        chain_urls = chain_urls[:MAX_REDIRECTS+1]

    domains = set()
    for u in chain_urls:
        d = normal_from_url(u)
        domains.add(d)

    added = add_domains_to_whitelist(domains)

    ok, msg = reload_squid()

    result = {
        "start_url": data,
        "chain_urls": chain_urls,
        "domains_extracted": list(domains),
        "domains_added": added,
        "squid_reload_ok": ok,
        "squid_msg": msg
    }
    return jsonify(result), (200 if ok else 500)

@app.route("/ping")
def ping():
    return "ok"

if __name__ == "__main__":
    print("Starting redirect resolver on http://%s:%d" % (LISTEN_HOST, LISTEN_PORT))
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
