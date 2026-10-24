# Hacker's Dashboard

Public, privacy-preserving dashboard for the Hacker Trap honeypot.

## Events
- HTTP request ("knock")
- POST to the decoy login route ("password attempt"); request bodies and credentials are never parsed or stored
- Exploratory requests to common admin paths
- Server errors

The dashboard intentionally does not display IP addresses, user-agent strings, query values, request bodies, or credentials. It does not claim that a real compromise occurred. The honeypot is a decoy application and has no real protected system to be entered.

## Required Railway variables
- `DATABASE_URL`: Railway PostgreSQL connection URL
- `INGEST_TOKEN`: long random shared secret; configure the same value on the honeypot service

## Ingestion
The honeypot sends JSON to `POST /ingest` with `Authorization: Bearer <INGEST_TOKEN>`.
The dashboard's public read APIs are `GET /api/dashboard/summary` and `GET /api/dashboard/events`.

Do not expose the database publicly. Use Railway private networking for service-to-service connections. Keep the ingestion token secret.
