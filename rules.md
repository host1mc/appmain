# Project Rules

## Security Priorities

- **app1 is the ONLY main security priority.** All hardening, review, and security effort must focus on app1. Do not spend security effort on db_admin or admin.

## Frontend / Backend Boundary (applies to app1/)

- The frontend (`frontend.py`, `asgi_panel.py`, `panel_app`, `static/`, `templates/`) must **NEVER** import `database.py` (db) or `engine.py`/`engine_client.py` (engine) directly.
- The frontend must never open DB connections, read DB credentials, or call engine internals.
- All data access and engine operations MUST go through the backend (`backend.py`) via its API/verification layer.
- Every frontend-originated request must be verified (authenticated/authorized) by the backend before touching the database or engine.
- The panel follows the same rule as app1: panel code never imports db or engine directly; everything is done through backend verification.

## db_admin and admin

- No security work is needed in `db_admin/` and `admin/`. Do not add security checks, auth hardening, or security review for these apps.
