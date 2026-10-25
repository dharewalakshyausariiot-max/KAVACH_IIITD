# Companion backend

Start the agent with `npx tsx src/server.ts` from the agent directory. The server
listens on 127.0.0.1:8787. Set `OPENAI_API_KEY` for non-crisis replies; optionally
set `COMPANION_MODEL` (default `gpt-4o-mini`).

`POST /companion` accepts exactly `{ "message": "I feel overwhelmed" }`.
Responses contain `reply`, `crisis`, `isDemo: false`, and `status`.
Status is `crisis`, `live`, or `unavailable` (HTTP 503). Crisis responses also
contain India-specific contacts. The deterministic keyword pre-check runs
without an API key and before network access. It is a conservative keyword
check, not a clinical assessment, and cannot detect every crisis.

Requests are limited to 20 KB and messages to 4000 characters. Replies are
limited to 1200 characters and model generation to 240 tokens. Responses use
Cache-Control: no-store. Messages are not persisted or logged by this code;
non-crisis text is sent to the configured model provider. Do not send images
or identifying details. Only the two exact approved HTTPS destinations are
accepted in generated output; unsafe links trigger a fixed grounding reply.
Provider failures are explicit and never substituted with demo data.

Related Python endpoints:
- `POST /api/evidence-pdf`: EvidenceCase metadata; requires `CERT_SECRET`.
  `is_demo`, `isDemo`, or legacy `is_mock` truthy flags mark the dossier as
  demo, with status `demo`, `isDemo: true`, and a DEMO DATA watermark per page.
  The seal authenticates canonical metadata, not the PDF file bytes.
- `POST /api/notice-draft`: `{ platform, url, host }`, with optional `isDemo`.
  Host is null or an EvidenceHost metadata object. Returns text, official
  abuse-desk mappings, and separately marked unverified caller host contacts.
  Notices contain completion placeholders and are never sent by this route.

Official references: https://telegram.org/faq and
https://support.reddithelp.com/hc/en-us/articles/360043513951;
https://www.copyright.gov/512/; https://112.gov.in/about.
