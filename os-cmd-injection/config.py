"""
Centralised configuration for the command-injection demo app.
Keeping these in one place (instead of scattered magic numbers/strings in
app.py) is standard practice and makes the security-relevant constants easy
to find and explain at the viva.
"""

import re

# Allow-list pattern used by the SECURE route: letters, digits, dots, hyphens only.
HOST_PATTERN = r"^[A-Za-z0-9.-]{1,253}$"
HOST_RE = re.compile(HOST_PATTERN)

# How long (seconds) we let the ping subprocess run before giving up.
COMMAND_TIMEOUT_SECONDS = 5

# How many past attempts to keep in the on-page history (per route).
HISTORY_LIMIT = 10

# Where activity is logged (created automatically if missing).
LOG_DIR = "logs"
LOG_FILE = "logs/activity.log"
