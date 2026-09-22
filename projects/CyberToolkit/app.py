"""
CyberToolkit — main Flask application.

Registers every tool's routes. Each tool's core logic lives in its own
module (modules/port_scanner.py, modules/dns_lookup.py,
modules/hash_cracker/, modules/whois/) — this file only wires HTTP
requests to those modules and renders templates.
"""

import os

from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

from modules.port_scanner import scan_range, PortScannerError
from modules.dns_lookup import lookup_domain, DnsLookupError, SUPPORTED_RECORD_TYPES

from modules.hash_cracker.engine import engine as hc_engine
from modules.hash_cracker.analyzer import analyze as hc_analyze_hash
from modules.hash_cracker import validators as hc_validators
from modules.hash_cracker.algorithms import SUPPORTED as HC_ALGORITHMS
from modules.hash_cracker.strategies.dictionary import build_candidates as hc_dict_candidates
from modules.hash_cracker.strategies.brute_force import build_candidates as hc_bf_candidates
from modules.hash_cracker.strategies.rainbow import is_compatible as hc_rainbow_compatible
from modules.hash_cracker.rainbow_table import recommended_params as hc_rainbow_recommended_params

from modules.whois.whois_lookup import lookup_domain as whois_lookup_domain
from modules.whois.validators import WhoisValidationError


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB — cap les uploads de wordlist

HC_WORDLIST_DIR = os.path.join(app.root_path, "wordlists")
os.makedirs(HC_WORDLIST_DIR, exist_ok=True)
HC_ALLOWED_WORDLIST_EXTENSIONS = {".txt"}

# Resource limits for rainbow tables — bounds worst-case runtime regardless
# of the time estimate, independent safety net.
HC_RAINBOW_MAX_TABLE_SIZE = 200_000
HC_RAINBOW_MAX_CHAIN_LENGTH = 2_000


def _hc_error(message, status_code=400, **extra):
    return jsonify(error=message, **extra), status_code


def _whois_error(message, status_code=400, **extra):
    return jsonify(error=message, **extra), status_code


# ===========================================================================
# HOME
# ===========================================================================

@app.route("/")
def home():
    return render_template("index.html", active="home")


# ===========================================================================
# PORT SCANNER — unchanged from your version
# ===========================================================================

@app.route("/port-scanner", methods=["GET", "POST"])
def port_scanner():
    if request.method == "GET":
        return render_template(
            "port_scanner.html", active="port-scanner",
            open_ports=None, known_ports=None, duration=None, error=None,
        )

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    payload = request.get_json(silent=True) or request.form

    try:
        report = scan_range(
            target=str(payload.get("target", "")),
            start_port=int(payload.get("start_port", 1)),
            end_port=int(payload.get("end_port", 1024)),
            timeout=float(payload.get("timeout", 0.5)),
            threads=int(payload.get("threads", 100)),
        )
    except (PortScannerError, ValueError, TypeError) as e:
        error = str(e)
        if is_ajax:
            return jsonify(error=error), 400
        return render_template(
            "port_scanner.html", active="port-scanner",
            open_ports=None, known_ports=None, duration=None, error=error,
        )

    if is_ajax:
        return jsonify(
            open_ports=report["open_ports"],
            known_ports=report["known_ports"],
            duration=report["duration"],
        )

    return render_template(
        "port_scanner.html", active="port-scanner",
        open_ports=report["open_ports"], known_ports=report["known_ports"],
        duration=report["duration"], error=None,
    )


# ===========================================================================
# DNS LOOKUP — unchanged from your version
# ===========================================================================

@app.route("/dns-lookup", methods=["GET", "POST"])
def dns_lookup():
    if request.method == "GET":
        return render_template(
            "dns_lookup.html", active="dns-lookup",
            supported_types=SUPPORTED_RECORD_TYPES,
            domain=None, results=None, found_count=None, duration=None, error=None,
        )

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    payload = request.get_json(silent=True)

    if payload is not None:
        domain = str(payload.get("domain", ""))
        record_types = payload.get("record_types") or []
        timeout = payload.get("timeout", 5.0)
    else:
        domain = request.form.get("domain", "")
        record_types = request.form.getlist("record_types")
        timeout = request.form.get("timeout", 5.0)

    try:
        report = lookup_domain(domain=domain, record_types=record_types, timeout=float(timeout))
    except (DnsLookupError, ValueError, TypeError) as e:
        error = str(e)
        if is_ajax:
            return jsonify(error=error), 400
        return render_template(
            "dns_lookup.html", active="dns-lookup",
            supported_types=SUPPORTED_RECORD_TYPES,
            domain=None, results=None, found_count=None, duration=None, error=error,
        )

    if is_ajax:
        return jsonify(
            domain=report["domain"], results=report["results"],
            found_count=report["found_count"], duration=report["duration"],
        )

    return render_template(
        "dns_lookup.html", active="dns-lookup",
        supported_types=SUPPORTED_RECORD_TYPES,
        domain=report["domain"], results=report["results"],
        found_count=report["found_count"], duration=report["duration"], error=None,
    )


# ===========================================================================
# HASH CRACKER — updated to the final engine (estimate + confirmation +
# real rainbow table with table_size/chain_length + resource caps)
# ===========================================================================

@app.route("/hash-cracker")
def hash_cracker():
    return render_template("hash_cracker.html", active="hash-cracker")


@app.route("/api/hash-cracker/analyze", methods=["POST"])
def hc_analyze():
    payload = request.get_json(silent=True) or {}
    try:
        hash_value = hc_validators.validate_hash_input(payload.get("hash_value", ""))
    except hc_validators.ValidationError as e:
        return _hc_error(str(e))
    return jsonify(analysis=hc_analyze_hash(hash_value))


@app.route("/api/hash-cracker/wordlists", methods=["GET"])
def hc_list_wordlists():
    names = sorted(
        f for f in os.listdir(HC_WORDLIST_DIR)
        if os.path.isfile(os.path.join(HC_WORDLIST_DIR, f)) and f.lower().endswith(".txt")
    )
    return jsonify(wordlists=names)


@app.route("/api/hash-cracker/wordlists/upload", methods=["POST"])
def hc_upload_wordlist():
    if "file" not in request.files:
        return _hc_error("No file uploaded.")

    file = request.files["file"]
    if not file.filename:
        return _hc_error("No file selected.")

    filename = secure_filename(file.filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in HC_ALLOWED_WORDLIST_EXTENSIONS:
        return _hc_error("Only .txt wordlists are accepted.")

    dest = os.path.join(HC_WORDLIST_DIR, filename)
    file.save(dest)
    return jsonify(name=filename)


@app.route("/api/hash-cracker/estimate", methods=["POST"])
def hc_estimate():
    """
    Feasibility check BEFORE starting a brute-force job. The frontend calls
    this first, shows the projected time, and only calls /start/brute_force
    with confirmed=true if the user accepts an over-threshold estimate.
    """
    payload = request.get_json(silent=True) or {}
    try:
        algorithm = hc_validators.validate_algorithm(payload.get("algorithm", ""), list(HC_ALGORITHMS))
        charset = hc_validators.validate_charset(
            bool(payload.get("lowercase")), bool(payload.get("uppercase")),
            bool(payload.get("numbers")), bool(payload.get("symbols")),
        )
        min_len, max_len = hc_validators.validate_length_range(
            int(payload.get("min_length", 1)), int(payload.get("max_length", 4)),
        )
    except (hc_validators.ValidationError, ValueError, TypeError) as e:
        return _hc_error(str(e))

    estimate = hc_engine.estimate(algorithm, len(charset), min_len, max_len)
    return jsonify(estimate=estimate)


@app.route("/api/hash-cracker/start/dictionary", methods=["POST"])
def hc_start_dictionary():
    payload = request.get_json(silent=True) or {}

    try:
        hash_value = hc_validators.validate_hash_input(payload.get("hash_value", ""))
        algorithm = hc_validators.validate_algorithm(payload.get("algorithm", ""), list(HC_ALGORITHMS))
        wordlist_path = hc_validators.validate_wordlist_name(payload.get("wordlist", ""), HC_WORDLIST_DIR)
        salt = (payload.get("salt") or "").strip() or None
        salt_order = hc_validators.validate_salt_order(payload.get("salt_order", "suffix"))
        transformations = payload.get("transformations") or []
    except hc_validators.ValidationError as e:
        return _hc_error(str(e))

    candidates = hc_dict_candidates(wordlist_path, transformations=transformations)
    job = hc_engine.start_job(
        hash_value=hash_value, algorithm=algorithm, strategy_name="dictionary",
        candidate_iterable=candidates, salt=salt, salt_order=salt_order,
    )
    return jsonify(job_id=job.job_id, snapshot=job.snapshot())


@app.route("/api/hash-cracker/start/brute_force", methods=["POST"])
def hc_start_bruteforce():
    payload = request.get_json(silent=True) or {}

    try:
        hash_value = hc_validators.validate_hash_input(payload.get("hash_value", ""))
        algorithm = hc_validators.validate_algorithm(payload.get("algorithm", ""), list(HC_ALGORITHMS))
        charset = hc_validators.validate_charset(
            bool(payload.get("lowercase")), bool(payload.get("uppercase")),
            bool(payload.get("numbers")), bool(payload.get("symbols")),
        )
        min_len, max_len = hc_validators.validate_length_range(
            int(payload.get("min_length", 1)), int(payload.get("max_length", 4)),
        )
        salt = (payload.get("salt") or "").strip() or None
        salt_order = hc_validators.validate_salt_order(payload.get("salt_order", "suffix"))
    except (hc_validators.ValidationError, ValueError, TypeError) as e:
        return _hc_error(str(e))

    estimate = hc_engine.estimate(algorithm, len(charset), min_len, max_len)

    if not estimate["feasible"] and not payload.get("confirmed"):
        return _hc_error(
            "Estimated time exceeds the reasonable local limit. "
            "Resend with \"confirmed\": true to run it anyway.",
            status_code=422, estimate=estimate, requires_confirmation=True,
        )

    candidates = hc_bf_candidates(charset, min_len, max_len)
    job = hc_engine.start_job(
        hash_value=hash_value, algorithm=algorithm, strategy_name="brute_force",
        candidate_iterable=candidates, total_estimate=estimate["total_candidates"],
        estimated_seconds=estimate["estimated_seconds"], salt=salt, salt_order=salt_order,
    )
    return jsonify(job_id=job.job_id, snapshot=job.snapshot(), estimate=estimate)


@app.route("/api/hash-cracker/start/rainbow", methods=["POST"])
def hc_start_rainbow():
    payload = request.get_json(silent=True) or {}

    try:
        hash_value = hc_validators.validate_hash_input(payload.get("hash_value", ""))
        algorithm = hc_validators.validate_algorithm(payload.get("algorithm", ""), list(HC_ALGORITHMS))
        charset = hc_validators.validate_charset(
            bool(payload.get("lowercase")), bool(payload.get("uppercase")),
            bool(payload.get("numbers")), bool(payload.get("symbols")),
        )
        length = hc_validators.validate_single_length(int(payload.get("length", 4)))
    except (hc_validators.ValidationError, ValueError, TypeError) as e:
        return _hc_error(str(e))

    analysis = hc_analyze_hash(hash_value)
    if not hc_rainbow_compatible(analysis):
        return _hc_error(
            "Rainbow table strategy is incompatible with this hash "
            "(salted or structured formats need a table per salt value).",
            status_code=422,
        )

    space_size = len(charset) ** length
    defaults = hc_rainbow_recommended_params(space_size)
    table_size = min(int(payload.get("table_size") or defaults["table_size"]), HC_RAINBOW_MAX_TABLE_SIZE)
    chain_length = min(int(payload.get("chain_length") or defaults["chain_length"]), HC_RAINBOW_MAX_CHAIN_LENGTH)

    total_ops = table_size * chain_length + chain_length * chain_length
    estimate = hc_engine.estimate_from_total(algorithm, total_ops)

    if not estimate["feasible"] and not payload.get("confirmed"):
        return _hc_error(
            "Estimated time exceeds the reasonable local limit. "
            "Resend with \"confirmed\": true to run it anyway.",
            status_code=422, estimate=estimate, requires_confirmation=True,
        )

    job = hc_engine.start_rainbow_job(
        hash_value=hash_value, algorithm=algorithm, charset=charset, length=length,
        table_size=table_size, chain_length=chain_length,
        estimated_seconds=estimate["estimated_seconds"],
    )
    return jsonify(job_id=job.job_id, snapshot=job.snapshot(), estimate=estimate,
                    table_size=table_size, chain_length=chain_length)


@app.route("/api/hash-cracker/jobs/<job_id>/status", methods=["GET"])
def hc_job_status(job_id):
    job = hc_engine.get(job_id)
    if job is None:
        return _hc_error("Unknown job_id.", status_code=404)
    return jsonify(snapshot=job.snapshot())


@app.route("/api/hash-cracker/jobs/<job_id>/pause", methods=["POST"])
def hc_job_pause(job_id):
    job = hc_engine.get(job_id)
    if job is None:
        return _hc_error("Unknown job_id.", status_code=404)
    job.pause()
    return jsonify(snapshot=job.snapshot())


@app.route("/api/hash-cracker/jobs/<job_id>/resume", methods=["POST"])
def hc_job_resume(job_id):
    job = hc_engine.get(job_id)
    if job is None:
        return _hc_error("Unknown job_id.", status_code=404)
    job.resume()
    return jsonify(snapshot=job.snapshot())


@app.route("/api/hash-cracker/jobs/<job_id>/stop", methods=["POST"])
def hc_job_stop(job_id):
    job = hc_engine.get(job_id)
    if job is None:
        return _hc_error("Unknown job_id.", status_code=404)
    job.stop()
    return jsonify(snapshot=job.snapshot())


# ===========================================================================
# WHOIS — was GET-only, now handles POST too (lookup actually works)
# ===========================================================================

@app.route("/whois", methods=["GET", "POST"])
def whois():
    if request.method == "GET":
        return render_template("whois.html", active="whois")

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    payload = request.get_json(silent=True) or request.form
    domain = payload.get("domain", "")

    try:
        result = whois_lookup_domain(domain)
    except WhoisValidationError as e:
        error = str(e)
        if is_ajax:
            return jsonify(error=error), 400
        return render_template("whois.html", active="whois", error=error, domain=domain)

    if is_ajax:
        return jsonify(result=result)
    return render_template("whois.html", active="whois", result=result)


# ===========================================================================
# SETTINGS
# ===========================================================================

@app.route("/settings")
def settings():
    return render_template("settings.html", active="settings")


# ===========================================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)