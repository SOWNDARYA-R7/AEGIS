import json
import logging
from datetime import datetime
from flask import Flask, abort, jsonify, render_template_string, request

app = Flask(__name__)

# Configure raw structured logging
LOG_FILE = "access_logs.json"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(message)s")

# Global set for blocked IPs (Mitigation Agent will update this)
BLOCKED_IPS = set()


@app.before_request
def inspect_and_log():
    client_ip = request.remote_addr or "127.0.0.1"

    # 1. Mitigation Check: Block if IP is blacklisted
    if client_ip in BLOCKED_IPS:
        abort(403, description="Access Denied by Autonomous SOC Framework.")

    # 2. Extract structured request parameters
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "client_ip": client_ip,
        "method": request.method,
        "path": request.path,
        "query_params": request.args.to_dict(),
        "headers": dict(request.headers),
        "body": request.get_data(as_text=True),
    }

    # Append log entry to disk
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")


@app.route("/")
def home():
    return render_template_string("""
        <h2>Target Enterprise Portal</h2>
        <form action="/search" method="GET">
            <input type="text" name="q" placeholder="Search database or enter query...">
            <button type="submit">Execute</button>
        </form>
    """)


@app.route("/search")
def search():
    query = request.args.get("q", "")
    # Simulating Vulnerable Query Execution
    return jsonify({"status": "success", "result": f"Executed query for: {query}"})


@app.route("/admin/block_ip", methods=["POST"])
def block_ip_api():
    """Internal API used by the Closed-Loop Mitigation agent."""
    data = request.get_json() or {}
    ip = data.get("ip")
    if ip:
        BLOCKED_IPS.add(ip)
        return jsonify({"status": "blocked", "ip": ip})
    return jsonify({"status": "error", "message": "No IP provided"}), 400


if __name__ == "__main__":
    app.run(port=5000, debug=False)