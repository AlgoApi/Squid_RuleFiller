from flask import Flask, request, jsonify, abort
import requests
import tldextract
import subprocess
import os
import hmac
from logging.handlers import RotatingFileHandler
import sys
import threading
import traceback
from werkzeug.exceptions import HTTPException
import logging
from flask import got_request_exception

WHITELIST_PATH = r"C:\Squid\etc\squid\whitelist.txt"
SQUID_BIN = r"C:\Squid\bin\squid.exe"
PYTHON_VVER = "1.246.43" # os.getenv("PYTHON_VVER")
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

@app.errorhandler(HTTPException)
def handle_http_exception(e: HTTPException):
    # e.code, e.description, e.name
    logger.warning("HTTP exception: %s %s %s from %s", e.code, e.name, e.description, request.remote_addr)
    payload = {
        "error": "http_error",
        "code": e.code,
        "name": e.name,
        "description": e.description
    }
    return jsonify(payload), e.code

# 2) generic exception handler — обязательно возвращает Response
@app.errorhandler(Exception)
def handle_all_exceptions(e):
    if isinstance(e, HTTPException):
        return handle_http_exception(e)

    logger.exception("Unhandled exception (returned 500) during request %s %s: %s", request.method, request.path, e)

    return jsonify({"error": "internal_server_error"}), 500

# Перехват необработанных исключений в основном потоке
def handle_uncaught_exception(exc_type, exc_value, exc_tb):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return
    logger.critical("Uncaught exception", exc_info=(exc_type, exc_value, exc_tb))

sys.excepthook = handle_uncaught_exception

# Перехват необработанных исключений в потоках
def thread_excepthook(args):
    # args: threading.ExceptHookArgs with .exc_type/.exc_value/.exc_traceback/.thread
    logger.critical("Uncaught thread exception in %s", getattr(args, "thread", None), exc_info=(args.exc_type, args.exc_value, args.exc_traceback))

threading.excepthook = thread_excepthook

# Перехват исключений в обработках Flask
def log_flask_exception(sender, exception, **extra):
    logger.exception("Unhandled exception during request: %s", exception)

got_request_exception.connect(log_flask_exception, app)

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
    logger.info("resolving for {%s}" % data)

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
    try:
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
            logger.error("not resolved: \n{%s: added=%s squid_ok=%s}", data, added, ok)
        return jsonify(result), (200 if ok else 500)
    except Exception as e:
        logger.exception("Error in resolve_redirects for %s", data)
        # возвращаем понятный JSON и 500
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500

@app.route("/ping")
def ping():
    logger.debug("ping")
    return "СЮДА СМОТРИ!"

@app.route("/favicon.ico")
def favicon():
    return ("", 204)

if __name__ == "__main__":
    logger.info("Starting redirect resolver on http://%s:%d" % (LISTEN_HOST, LISTEN_PORT))
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
