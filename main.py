from flask import Flask, request, jsonify, abort
import requests
import tldextract
import subprocess
import os
import hmac
import logging
from logging.handlers import RotatingFileHandler

WHITELIST_PATH = r"C:\Squid\etc\squid\whitelist.txt"
SQUID_BIN = r"C:\Squid\bin\squid.exe"
PYTHON_VVER = os.getenv("PYTHON_VVER") #1.246.43
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5566
REQUEST_TIMEOUT = 15
MAX_REDIRECTS = 10
VERIFY_SSL = False
LOG_FILE = os.path.join(os.path.dirname(__file__), "squid_autofiller.log")

from flask_cors import CORS
app = Flask(__name__)
CORS(app)

logger = logging.getLogger('squid_autofiller')
logger.setLevel(logging.INFO)

ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
ch.setFormatter(fmt)
logger.addHandler(ch)

fh = RotatingFileHandler(LOG_FILE, encoding='utf-8')
fh.setLevel(logging.INFO)
fh.setFormatter(fmt)
logger.addHandler(fh)

logger.info("Logger initialized. Log file: %s", LOG_FILE)

def version(ver):
    return hmac.compare_digest(ver or "", PYTHON_VVER)

def normal_from_url(url):
    try:
        te = tldextract.extract(url)
        if te.domain:
            domain = te.domain + (("." + te.suffix) if te.suffix else "")
            return domain.lower()
    except Exception:
        logger.debug("normalazing failed")
        return None
    return None

def add_domains_to_whitelist(domains):
    # read existing lines
    if not os.path.exists(WHITELIST_PATH):
        os.makedirs(WHITELIST_PATH, exist_ok=True)
        open(WHITELIST_PATH, "w", encoding="utf-8").close()
    with open(WHITELIST_PATH, "r", encoding="utf-8") as f:
        existing = {ln.strip().lower() for ln in f if ln.strip()}
    logger.debug("existing: \n{%s}" % existing)
    added = []
    with open(WHITELIST_PATH, "a", encoding="utf-8") as f:
        for d in domains:
            entry = "." + d if not d.startswith(".") else d
            if entry not in existing:
                f.write(entry + "\n")
                existing.add(entry)
                added.append(entry)
                logger.info("added: \n{%s}" % entry)
            else:
                logger.info("{%s} already exists" % entry)
    return added

def reload_squid():
    try:
        res = subprocess.run([SQUID_BIN, "-k", "reconfigure"], capture_output=True, text=True, check=True)
        logger.info("restart!")
        return True, res.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error("Failed to restart")
        return False, (e.stdout + e.stderr)

@app.route("/resolve_redirects", methods=["GET"])
def resolve_redirects():
    vver = request.args.get("vver", "")
    if not version(vver):
        logger.info("vver not found")
        abort(403)
    data = request.args.get("url")
    if not data or "http" not in data:
        logger.warning("No URL provided")
        return jsonify({"error":"No URL provided"}), 400

    try:
        session = requests.Session()
        resp = session.get(data, allow_redirects=True, timeout=REQUEST_TIMEOUT, verify=VERIFY_SSL)
        logger.info("request!")
    except requests.RequestException as ex:
        logger.error("request_failed: \n{%s}" % str(ex))
        return jsonify({"error": "request_failed", "details": str(ex)}), 502

    chain_urls = []
    for r in resp.history:
        chain_urls.append(r.url)
    chain_urls.append(resp.url)
    logger.info("get history!")

    if len(chain_urls) > MAX_REDIRECTS + 1:
        chain_urls = chain_urls[:MAX_REDIRECTS+1]

    domains = set()
    for u in chain_urls:
        d = normal_from_url(u)
        domains.add(d)
    logger.info("get domains!")

    logger.info("adding domains!")
    added = add_domains_to_whitelist(domains)

    logger.info("reloading squid!")
    ok, msg = reload_squid()

    result = {
        "start_url": data,
        "chain_urls": chain_urls,
        "domains_extracted": list(domains),
        "domains_added": added,
        "squid_reload_ok": ok,
        "squid_msg": msg
    }
    logger.info("RESULT!")

    if ok:
        logger.info("RESOLVE!")
    else:
        logger.error("not resolved: \n{%s}" % result)

    return jsonify(result), (200 if ok else 500)

@app.route("/ping")
def ping():
    logger.debug("ping")
    return "СЮДА СМОТРИ!"

if __name__ == "__main__":
    logger.info("Starting redirect resolver on http://%s:%d" % (LISTEN_HOST, LISTEN_PORT))
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
