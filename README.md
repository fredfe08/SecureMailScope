# SecureMailScope

**Smart India Hackathon 2026 — PS SIH26159 — National Technical Research Organisation (NTRO)**
Domain: Cybersecurity / Digital Forensics

SecureMailScope turns raw evidence about a mail server's security posture — either a packet capture, a domain name, or both — into a structured, evidence-first report. Every finding is reported as **OBSERVED**, **NOT_FOUND**, **UNKNOWN**, or **INSUFFICIENT_EVIDENCE**, never as an assumed or inferred conclusion. The project does not perform offensive scanning, does not guess at events that weren't captured/observed, and does not treat "record exists" as equivalent to "security posture is strong."

---

## Repository Structure

```text
SecureMailScope/
├── M1/                     # PCAP / network evidence extraction (Python + TShark)
│   ├── M1_ALL/              # extraction pipeline modules
│   ├── test_core.py         # 14 unit tests
│   ├── evidence.schema.json # JSON schema for M1's output
│   └── sample_evidence.json # example output
├── tls-engine/              # TLS/certificate scan + SPF/DKIM/DMARC + scoring (Python)
│   ├── main.py               # pipeline coordinator
│   ├── tls_scanner.py        # live TLS/cert scan of the mail server
│   ├── spf_checker.py / dkim_checker.py / dmarc_checker.py
│   ├── analyzer.py           # produces security_score + risk_level
│   └── test_main.py / test_security_fixes.py  # 11 unit tests
├── backend/                 # FastAPI orchestrator (API layer for the frontend)
│   ├── main.py                # /scan, /health, /history endpoints
│   └── scans.db               # SQLite scan history
├── M4+M5/                   # "Postflight" web app — React + TypeScript + Vite
│   ├── src/lib/checks/         # SPF/DKIM/DMARC/domain/TLS checks (live DNS)
│   ├── src/lib/pcap/           # from-scratch classic-pcap parser + TLS analyzer
│   ├── src/components/         # UI (sidebar, score gauge, report views)
│   └── supabase/functions/     # AI-summary edge function (OpenAI call, key stays server-side)
├── frontend-backup/         # earlier static HTML prototype (kept for reference only)
└── data/                    # shared upload directory
```

---

## How the Pieces Fit Together

SecureMailScope currently has **two independent evidence paths** that both feed the same idea (an evidence-first email security report), plus an orchestrator layer meant to unify them:

```text
Path A — Passive PCAP forensics (Python)
  PCAP/PCAPNG file
        |
        v
  M1 (TShark extraction: protocol detection, TCP streams,
      STARTTLS, TLS handshake stages, certificates)
        |
        v
  evidence.json  (includes a "handoff" block with a candidate domain)
        |
        v
  tls-engine (live TLS/cert scan of that domain + SPF/DKIM/DMARC
              DNS checks + security_score / risk_level)
        |
        v
  analysis.json

Path B — Client-side web app ("Postflight")
  Domain name  ------------------------------\
                                              v
  PCAP file (classic .pcap only) --> M4+M5's own pcap parser + TLS analyzer
                                              |
                                              v
                              live SPF/DKIM/DMARC/domain checks (DNS-over-HTTPS)
                                              |
                                              v
                          scored report in-browser (+ optional AI summary, PDF export)

Orchestrator (WIP)
  backend/main.py exposes POST /scan, intended to accept a PCAP upload,
  call M1, normalize findings into one schema, score risk, and store
  history in SQLite for the frontend to query.
```

### Current integration status — read this before assuming something is wired up

- **`backend/main.py` runs in mock mode by default** (`USE_MOCKS=true`). Its call into M1 (`run_m1_analyzer`) points at a placeholder script path and hasn't been updated to invoke M1's real CLI (`M1_ALL/cli.py`) or consume its actual JSON shape yet.
- **`M4+M5` does not call `backend/` at all.** It has its own from-scratch pcap parser and its own live DNS checks, and produces its report entirely client-side. It is a complete, independently runnable app, not (yet) a frontend for `backend/`.
- **`tls-engine` is file-driven, not an HTTP service.** It expects an `evidence.json` (in M1's output shape) in its working directory and writes an updated `evidence.json` plus `analysis.json` — there's no API layer in front of it yet.
- **M1's Python package layout doesn't match its own `pyproject.toml`.** The module lives in `M1/M1_ALL/`, but `pyproject.toml` and `M1/README.md` reference a `securemailscope_m1/` package — rename the folder (or update `pyproject.toml`) before `pip install -e .` will work.

None of this is a blocker for demoing each piece on its own — it's the honest state of integration so nobody assumes a wire exists that isn't there yet.

---

## Evidence States (shared vocabulary across every module)

| State | Meaning |
|---|---|
| `OBSERVED` | The evidence is directly present in the capture/scan. |
| `NOT_FOUND` | We looked for it and it is affirmatively absent. |
| `UNKNOWN` | Cannot be determined from the data available — not the same as `NOT_FOUND`. |
| `INSUFFICIENT_EVIDENCE` | A negative conclusion would be unsafe (e.g. a truncated capture) — we don't guess. |

STARTTLS specifically is tracked as **four separate facts** (`advertised`, `attempted`, `acknowledged_or_accepted`, `tls_followed`) rather than one boolean — a command being sent doesn't mean it succeeded, and a positive response doesn't mean TLS actually followed.

---

## M1 — PCAP / Network Evidence Extraction

Reads a `.pcap`/`.pcapng` file with TShark and reports SMTP/IMAP/POP3 traffic, TCP stream evidence, STARTTLS negotiation, TLS handshake stages, TLS versions, X.509 certificates, and basic capture-quality clues. Does not score risk, judge certificate trust, or perform live network access.

**Install**

```bash
sudo apt-get install -y tshark
cd M1
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -r requirements.txt
```

**Verify TShark fields (do this first — field names are version-sensitive)**

```bash
python -m M1_ALL.cli verify-fields --tshark /usr/bin/tshark
```

**Extract evidence**

```bash
python -m M1_ALL.cli extract capture.pcapng --tshark /usr/bin/tshark -o evidence.json
```

**Run tests**

```bash
python -m unittest discover -s . -p "test_core.py" -v   # 14 tests
```

Output includes an additive `handoff` object (`network`, `tls`, `m2` sections) so downstream modules get a candidate domain, hostname, TLS summary, and certificate details without re-parsing the capture. The `m2` section is populated with `null` SPF/DKIM/DMARC/risk fields — M1 intentionally does not perform DNS lookups or scoring.

---

## tls-engine — TLS/Certificate + Email Authentication Scoring

Consumes an `evidence.json` (in M1's shape), then:

1. Runs a live TLS/certificate scan of the mail server named in the handoff (`tls_scanner.py`)
2. Checks SPF, DKIM, and DMARC for the organizational domain via live DNS (`spf_checker.py`, `dkim_checker.py`, `dmarc_checker.py`)
3. Computes a `security_score` (starts at 100, deducts points per finding) and a `risk_level` (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`) in `analyzer.py`

A DKIM selector not being found is treated as inconclusive, not automatically as a failure — DNS has no record listing which selectors a domain uses, so the checker only probes common selector names.

**Install & run**

```bash
cd tls-engine
python -m venv venv && . venv/bin/activate    # Windows: .\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

This updates `evidence.json` in place and writes `analysis.json`.

**Run tests**

```bash
python -m unittest discover -v   # 11 tests, mocked DNS/network conditions
```

---

## backend — FastAPI Orchestrator

Intended to be the single API the frontend calls: accepts a PCAP upload, runs the extraction/scoring pipeline, normalizes findings into one `Finding` schema (`category`, `status`, `severity`, `evidence`, `recommendation`), computes a score via a simple severity-weighted risk engine, and stores scan history in SQLite.

**Run**

```bash
cd backend
python -m venv venv && . venv/bin/activate
pip install -r requirements.txt
python main.py     # serves on http://0.0.0.0:8000
```

**Endpoints:** `POST /scan` (upload a PCAP), `GET /health`, `GET /history/{filename}`.

Set `USE_MOCKS=false` once M1's real invocation path is fixed to run against actual extraction output instead of mock SPF/DKIM/DMARC/TLS values.

---

## M4+M5 — "Postflight" Web App

A self-contained React + TypeScript + Vite app that checks SPF, DKIM, DMARC, and DNS hygiene for a domain via live DNS-over-HTTPS lookups, and — if given a classic `.pcap` file — parses it itself (no TShark dependency: its own pcap reader, TCP stream reassembly, and TLS record scanner in `src/lib/pcap/`) to report the TLS version/cipher actually negotiated, including STARTTLS sessions where TLS starts mid-stream after plaintext commands. Produces a scored, plain-language report with an optional AI-written summary (via a Supabase Edge Function, so the OpenAI key never reaches the browser) and PDF export.

**Run**

```bash
cd M4+M5
npm install
cp .env.example .env   # fill in your Supabase project URL + publishable key
npm run dev
```

| Script | Purpose |
|---|---|
| `npm run dev` | Local dev server |
| `npm run build` | Production build |
| `npm run lint` / `npm run typecheck` | Static checks |

**Known limitations:** DKIM detection probes ~19 common selector names only (no DNS record enumerates selectors); only classic `.pcap` is supported — convert `.pcapng` first with `tshark -F pcap -w out.pcap -r in.pcapng`; TCP reassembly is sequence-ordered but not gap-aware, so it won't recover from packets genuinely missing mid-handshake.

See [`M4+M5/README.md`](./M4+M5/README.md) and [`M4+M5/SETUP_AI_SUMMARY.md`](./M4+M5/SETUP_AI_SUMMARY.md) for full setup details.

---

## frontend-backup

`ui_sih1.html` — an earlier static prototype UI, kept for reference. Not part of the active build.

---

## Team & Roles

| Member | Role | Primary module(s) |
|---|---|---|
| Aaryan Subhash Rana | M1 — Protocol / Network Extraction Engine | `M1/` |
| Ved Waghmare | M2 — TLS / Certificate Security Engine | `tls-engine/` (TLS/cert side) |
| Fredrick Felix Wilson | M3 — Backend Orchestrator & Evidence/Risk Engine | `backend/`, `tls-engine/` (scoring side) |
| Purva Majgaokar | M4 — Investigation Interface Lead | `M4+M5/` (report UI) |
| Vignesh Tondwalkar | M5 — AI Explanation & Reporting Lead | `M4+M5/` (AI summary, PDF export) |
| Kevin Arun | M6 — QA, Integration & Demo Lead | tests across all modules, integration |

---

## Disclaimer

This is a passive, evidence-based analysis tool built for a hackathon submission. It does not perform offensive scanning and should only be run against domains/mail infrastructure you own or are authorized to assess. Security scores and risk levels are project-defined heuristics, not an industry certification.
