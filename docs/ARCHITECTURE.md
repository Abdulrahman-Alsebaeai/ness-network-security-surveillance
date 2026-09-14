# NESS Architecture

NESS is structured as a Flask application backed by SQLite and a service-oriented `ness_core` package. Detection events are persisted first, then propagated through evidence, tracking, alerting, analysis, and reporting services. The frontend consumes the same SQLite-backed APIs and receives `data.changed` notifications via WebSocket; revision polling provides a fallback refresh mechanism.

The cyber range binds training services to localhost and maps them to logical topology nodes shown in the UI. This preserves an interactive demonstration while keeping scenarios constrained to the local project environment.
