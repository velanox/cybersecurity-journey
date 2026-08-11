import socket
import time

from flask import Flask, render_template, request, jsonify

from modules.port_scanner import scan_range, PortScannerError

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html", active="home")


@app.route("/port-scanner", methods=["GET", "POST"])
def port_scanner():
    if request.method == "GET":
        return render_template("port_scanner.html", active="port-scanner")

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
        return render_template("port_scanner.html", active="port-scanner", error=error)

    if is_ajax:
        return jsonify(
            open_ports=report["open_ports"],
            known_ports=report["known_ports"],
            duration=report["duration"],
        )

    return render_template(
        "port_scanner.html",
        active="port-scanner",
        open_ports=report["open_ports"],
        known_ports=report["known_ports"],
        duration=report["duration"],
    )


@app.route("/dns-lookup")
def dns_lookup():
    return render_template("dns_lookup.html", active="dns-lookup")


@app.route("/hash-cracker")
def hash_cracker():
    return render_template("hash_cracker.html", active="hash-cracker")


@app.route("/whois")
def whois():
    return render_template("whois.html", active="whois")


@app.route("/settings")
def settings():
    return render_template("settings.html", active="settings")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)