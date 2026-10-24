# HerGuard Backend

HerGuard is a privacy-first forensics, exposure mitigation, and legal takedown platform designed to detect deepfakes, track unauthorized public image exposures, and generate statutory takedown notices and cybercrime complaint drafts.

---

## Table of Contents

- [Core Design Notes](#core-design-notes)
- [Project Architecture](#project-architecture)
- [Prerequisites & Setup](#prerequisites--setup)
- [Running the Server](#running-the-server)
- [Environment Variables](#environment-variables)
- [Supabase Setup](#supabase-setup)
- [API Endpoints & cURL Examples](#api-endpoints--curl-examples)
  - [1. Health Check (`GET /api/health`)](#1-health-check-get-apihealth)
  - [2. Media Scan (`POST /api/scan`)](#2-media-scan-post-apiscan)
  - [3. Legal Notice Generation (`POST /api/notice`)](#3-legal-notice-generation-post-apinotice)
- [Running Tests](#running-tests)
- [Interactive API Docs (Swagger UI)](#interactive-api-docs-swagger-ui)

---

## Core Design Notes

1. **Zero Raw Image Storage**: The HerGuard backend never persists raw image bytes, binary payloads, base64 strings, or data URLs to databases, object stores, or local fallback files. The moment an image is validated, it is processed strictly in-memory.
2. **Cryptographic SHA-256 Evidence Hashing**: Every uploaded image is fingerprinted using a standard SHA-256 hex digest (`sha256_hex`). This 64-character hash serves as the immutable digital evidence identifier across evidence vaulting, exposure tracking, and legal notice generation.
3. **Simulated Deepfake Checks**: Detector output in this module is explicitly synthetic and simulated for demonstration purposes. Simulated scores are deterministic and reproducible based on image digests, but are clearly labeled as `simulated: true` and must not be used as courtroom forensic proof.
4. **Strict Draft-Only Legal Compliance**:
   - All notices produced by HerGuard are strictly pre-formatted drafts (`status="draft"`).
   - Notices are **never automatically sent** to any platform, host, or authority.
   - Every notice explicitly embeds statutory citations (DMCA 17 U.S.C. § 512(c), Indian IT Rules 2021 Rule 3(2)(b) 24-hour removal mandate, and IT Act 2000 Sections 66E & 67A).
   - All outputs include a mandatory legal disclaimer providing emergency reporting routes for India users (`https://cybercrime.gov.in` and national helpline `1930`).

---

## Project Architecture

```
backend/
├── .env.example          # Template for environment configuration
├── .gitignore            # Git exclusion rules
├── exposure.py           # Exposure discovery (mock or live TinyFish / RDAP)
├── forensics.py          # Image validation, SHA-256 digest, simulated detector
├── main.py               # FastAPI application routing and middleware
├── notices.py            # Legal takedown notice & cybercrime complaint generator
├── README.md             # Backend service documentation
├── requirements.txt      # Python dependencies
├── schemas.py            # Shared Pydantic request and response models
├── supabase_schema.sql   # SQL schema for evidence vault metadata table
├── test_api.py           # Integration tests for FastAPI endpoints
├── test_notices.py       # Unit tests for legal notice generation
└── vault.py              # Vault persistence (Supabase with JSONL fallback)
```

---

## Prerequisites & Setup

### 1. Prerequisites
- **Python**: 3.10+ (tested on Python 3.11)
- **pip** package installer

### 2. Create and Activate a Virtual Environment

**Windows (PowerShell):**
```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Copy the example configuration:
```bash
cp .env.example .env
```
*(On Windows PowerShell, use `Copy-Item .env.example .env`)*

By default, `.env.example` sets `USE_MOCK=true`, allowing the full backend to run locally without external cloud dependencies.

---

## Running the Server

Start the FastAPI application using `uvicorn` from the `backend/` directory:

```bash
uvicorn main:app --reload --port 8000
```

Once running:
- **API Base URL**: `http://localhost:8000`
- **Swagger UI (Interactive API Docs)**: `http://localhost:8000/docs`
- **ReDoc UI**: `http://localhost:8000/redoc`

---

## Environment Variables

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `USE_MOCK` | Boolean | `true` | When `true`, returns deterministic mock exposure matches and runs in demo mode without calling external APIs. |
| `CORS_ORIGINS` | Comma-separated strings | `*` | List of allowed CORS origin URLs (e.g. `http://localhost:3000,http://localhost:5173`). |
| `SUPABASE_URL` | URL | *(empty)* | HTTPS URL of your Supabase project instance (e.g. `https://xyzcompany.supabase.co`). |
| `SUPABASE_KEY` | String | *(empty)* | Supabase Service Role key (bypasses RLS to insert evidence metadata). |
| `TINYFISH_API_KEY` | String | *(empty)* | API key for the TinyFish automation engine (required only when `USE_MOCK=false`). |
| `TINYFISH_URL` | URL | *(empty)* | TinyFish `/v1/automation/run` endpoint URL for live exposure search. |

> **Note on Storage Fallback**: If `SUPABASE_URL` or `SUPABASE_KEY` are not configured or if remote calls fail, `vault.py` automatically preserves evidence metadata into a durable local JSONL file at `backend/data/vault_local.jsonl`.

---

## Supabase Setup

To persist metadata to a live Supabase PostgreSQL database:

1. Log into your [Supabase Dashboard](https://supabase.com/dashboard) and navigate to the **SQL Editor**.
2. Open and run the contents of [`backend/supabase_schema.sql`](supabase_schema.sql):
   ```sql
   -- Evidence metadata only; raw image bytes are not stored here.
   CREATE TABLE IF NOT EXISTS public.evidence_vault (
       id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
       case_id uuid NOT NULL,
       image_hash text NOT NULL,
       timestamp timestamptz NOT NULL DEFAULT now(),
       matched_urls jsonb NOT NULL DEFAULT '[]'::jsonb,
       status text NOT NULL DEFAULT 'pending'
   );

   ALTER TABLE public.evidence_vault ENABLE ROW LEVEL SECURITY;
   ```
3. Copy your project URL and `service_role` secret key from **Project Settings > API**.
4. Set `SUPABASE_URL` and `SUPABASE_KEY` in your `backend/.env` file.

---

## API Endpoints & cURL Examples

### 1. Health Check (`GET /api/health`)

Checks service health and indicates whether mock mode is currently enabled.

**Request:**
```bash
curl -X GET http://localhost:8000/api/health
```

**Response (HTTP 200):**
```json
{
  "status": "ok",
  "mock_mode": true
}
```

---

### 2. Media Scan (`POST /api/scan`)

Accepts an image upload (`image/jpeg`, `image/png`, or `image/webp` up to 10 MiB), computes its cryptographic SHA-256 fingerprint, performs deepfake analysis, searches for exposures, and stores metadata in the evidence vault.

**Request:**
```bash
curl -X POST http://localhost:8000/api/scan \
  -F "file=@/path/to/evidence.png;type=image/png"
```

**Response (HTTP 200):**
```json
{
  "case_id": "428ca4be-6238-4e8c-8c70-65ea7cfbfae6",
  "image_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "timestamp": "2026-10-24T09:30:00Z",
  "deepfake": {
    "is_deepfake": false,
    "confidence": 0.8872,
    "model": "herguard-simulated-v1",
    "simulated": true
  },
  "matches": [
    {
      "url": "https://mirror-1.example/images/e3b0c44298fc1c14",
      "similarity_score": 0.892,
      "host_details": {
        "domain": "mirror-1.example",
        "ip_address": "192.0.2.1",
        "hosting_provider": "Simulated registrar 1",
        "abuse_email": "abuse@mirror-1.example"
      }
    }
  ],
  "status": "completed"
}
```

*Note: Uploading an unsupported file format (e.g. `text/plain`) returns `HTTP 415 (Unsupported Media Type)`.*

---

### 3. Legal Notice Generation (`POST /api/notice`)

Generates a pre-formatted legal takedown notice (`"dmca"`) or a formal cybercrime complaint draft (`"cybercrime"`).

#### A. DMCA Takedown Notice (`notice_type: "dmca"`)

Cites DMCA 17 U.S.C. 512(c), platform non-consensual imagery policies, and India's IT Rules 2021 Rule 3(2)(b) (24-hour removal expectation).

**Request:**
```bash
curl -X POST http://localhost:8000/api/notice \
  -H "Content-Type: application/json" \
  -d '{
    "case_id": "428ca4be-6238-4e8c-8c70-65ea7cfbfae6",
    "matched_url": "https://mirror-1.example/images/e3b0c44298fc1c14",
    "requester_name": "Priya Sharma",
    "requester_email": "priya@example.com",
    "notice_type": "dmca"
  }'
```

**Response (HTTP 200):**
```json
{
  "case_id": "428ca4be-6238-4e8c-8c70-65ea7cfbfae6",
  "matched_url": "https://mirror-1.example/images/e3b0c44298fc1c14",
  "subject": "URGENT: Content Removal Notice (DMCA 17 U.S.C. 512(c) / IT Rules 2021) - Case 428ca4be-6238-4e8c-8c70-65ea7cfbfae6",
  "body": "TAKEDOWN NOTICE PURSUANT TO DMCA (17 U.S.C. § 512(c)) AND IT RULES 2021 RULE 3(2)(b)\n...",
  "recipient_email": "abuse@mirror-1.example",
  "status": "draft"
}
```

#### B. Cybercrime Complaint Draft (`notice_type: "cybercrime"`)

Cites the Information Technology Act 2000 (Sections 66E and 67A), host/registrar details, evidence hash, and formally requests FIR registration and official acknowledgement.

**Request:**
```bash
curl -X POST http://localhost:8000/api/notice \
  -H "Content-Type: application/json" \
  -d '{
    "case_id": "428ca4be-6238-4e8c-8c70-65ea7cfbfae6",
    "matched_url": "https://mirror-1.example/images/e3b0c44298fc1c14",
    "requester_name": "Priya Sharma",
    "requester_email": "priya@example.com",
    "notice_type": "cybercrime"
  }'
```

**Response (HTTP 200):**
```json
{
  "case_id": "428ca4be-6238-4e8c-8c70-65ea7cfbfae6",
  "matched_url": "https://mirror-1.example/images/e3b0c44298fc1c14",
  "subject": "Formal Cybercrime Complaint Draft: Violation of IT Act 2000 (Sections 66E & 67A) - Case 428ca4be-6238-4e8c-8c70-65ea7cfbfae6",
  "body": "COMPLAINT DRAFT FOR CYBER OFFENCES\n(Under Sections 66E and 67A of the Information Technology Act, 2000)\n...",
  "recipient_email": "abuse@mirror-1.example",
  "status": "draft"
}
```

---

## Running Tests

Execute the automated test suite using `pytest`:

```bash
# Run all tests
pytest

# Run tests with verbose output
pytest -v

# Run only notice generation unit tests
pytest backend/test_notices.py -v

# Run only API endpoint integration tests
pytest backend/test_api.py -v
```

---

## Interactive API Docs (Swagger UI)

FastAPI provides an automatic, interactive OpenAPI documentation interface. Once the server is running, visit:
- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)
