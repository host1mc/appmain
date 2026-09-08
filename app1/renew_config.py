"""Central knobs for the trial renew cycle and outgoing-email branding.

Set ``RENEW_CYCLE_DAYS`` and ``RENEW_WINDOW_DAYS`` in ``.env`` to retune the
trial clock without editing database.py. The cycle controls how long a renew
extends the account; the window controls when the Renew button opens.
"""

import os


def _env_int(name, default):
	try:
		return int(os.getenv(name, str(default)))
	except (TypeError, ValueError):
		return default


# Length of one trial / renew cycle, in days.
RENEW_CYCLE_DAYS = _env_int("RENEW_CYCLE_DAYS", 7)

# How many days before the trial deadline the first warning mail goes out.
RENEW_WARN_DAYS_BEFORE = _env_int("RENEW_WARN_DAYS_BEFORE", 3)

# How many days before the renew deadline the panel allows renewal.
RENEW_WINDOW_DAYS = _env_int("RENEW_WINDOW_DAYS", 3)

# Extra days after expiry before user workloads are removed.
RENEW_GRACE_DAYS = _env_int("RENEW_GRACE_DAYS", 1)

# Product brand shown in outgoing email (header, footer, subjects, From name).
BRAND_NAME = "End Host"

# Short mark for the round logo cell in the email header.
BRAND_INITIALS = "EH"
