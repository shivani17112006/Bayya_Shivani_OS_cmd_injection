"""
Web Server Security Assignment — IT-30001
Category: OS Command Injection
Variant:  In-band (command output returned directly in the response)

/vulnerable -> intentionally insecure implementation (for the exploit demo)
/secure     -> the same feature, fixed
/health     -> basic health check

Run only on your own machine / isolated VM. Do NOT deploy this publicly.
"""

import logging
import os
import platform
import subprocess
from datetime import datetime

from flask import Flask, render_template, request

from config import HOST_RE, COMMAND_TIMEOUT_SECONDS, HISTORY_LIMIT, LOG_DIR, LOG_FILE

app = Flask(__name__)

# --- Logging setup: every attempt (vulnerable or secure) is recorded with a
# timestamp. This is useful evidence for your report/viva, and is good
# practice in general (you always want an audit trail of what ran). ---
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

# --- In-memory history so the page visibly shows past attempts, newest
# first. Reset when the app restarts (no database needed for a demo). ---
history_vulnerable = []
history_secure = []


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _push_history(bucket, entry):
    bucket.insert(0, entry)
    del bucket[HISTORY_LIMIT:]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return {"status": "ok", "time": datetime.now().isoformat()}


# ---------------------------------------------------------------------------
# VULNERABLE implementation
# ---------------------------------------------------------------------------
@app.route("/vulnerable", methods=["GET", "POST"])
def cmd_vulnerable():
    """
    (a) VULNERABLE CODE PATH
    The user-supplied host is concatenated directly into a shell command
    string, and shell=True hands that string to the system shell. Any shell
    metacharacter the user includes (;  &&  |  `` ` `` etc.) is interpreted
    by the shell, not treated as part of the hostname.
    """
    output, command_shown, error = None, None, None
    if request.method == "POST":
        host = request.form.get("host", "").strip()[:200]  # basic length cap

        if not host:
            error = "Please enter a host."
        else:
            # --- VULNERABLE: shell=True + raw string concatenation ---
            command = f"ping -n 1 {host}" if _is_windows() else f"ping -c 1 {host}"
            command_shown = command
            try:
                result = subprocess.run(
                    command, shell=True, capture_output=True,
                    timeout=COMMAND_TIMEOUT_SECONDS, text=True,
                )
                output = (result.stdout or "") + (result.stderr or "")
            except subprocess.TimeoutExpired:
                output = "Command timed out."
            except Exception as e:  # noqa: BLE001 (demo only)
                output = f"Error: {e}"

            logging.info("VULNERABLE attempt | host=%r | command=%r", host, command)
            _push_history(history_vulnerable, {
                "time": datetime.now().strftime("%H:%M:%S"),
                "host": host,
                "command": command,
            })

    return render_template(
        "cmd_vulnerable.html",
        output=output, command_shown=command_shown, error=error,
        history=history_vulnerable,
    )


# ---------------------------------------------------------------------------
# SECURE implementation (mitigation implemented)
# ---------------------------------------------------------------------------
@app.route("/secure", methods=["GET", "POST"])
def cmd_secure():
    """
    (d) MITIGATION IMPLEMENTED
    1. No shell is invoked at all: subprocess.run([...], shell=False) passes
       the command as an argument vector, so shell metacharacters have no
       special meaning.
    2. Allow-list input validation: the host is also checked against a
       strict regex before use, as defence in depth.
    """
    output, error = None, None
    if request.method == "POST":
        host = request.form.get("host", "").strip()[:200]

        if not host:
            error = "Please enter a host."
        elif not HOST_RE.match(host):
            error = "Invalid host — only letters, digits, dots and hyphens are allowed."
            logging.warning("SECURE attempt BLOCKED | host=%r", host)
        else:
            try:
                # --- SECURE: argument vector, shell=False, validated input ---
                args = ["ping", "-n", "1", host] if _is_windows() else ["ping", "-c", "1", host]
                result = subprocess.run(
                    args, shell=False, capture_output=True,
                    timeout=COMMAND_TIMEOUT_SECONDS, text=True,
                )
                output = (result.stdout or "") + (result.stderr or "")
            except subprocess.TimeoutExpired:
                output = "Command timed out."
            except Exception as e:  # noqa: BLE001 (demo only)
                output = f"Error: {e}"

            logging.info("SECURE attempt ALLOWED | host=%r", host)
            _push_history(history_secure, {
                "time": datetime.now().strftime("%H:%M:%S"),
                "host": host,
                "status": "allowed",
            })

        if error:
            _push_history(history_secure, {
                "time": datetime.now().strftime("%H:%M:%S"),
                "host": host,
                "status": "blocked",
            })

    return render_template(
        "cmd_secure.html", output=output, error=error, history=history_secure,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
