# Postflight (SecureMailScope)

Postflight checks the email identity controls attached to a domain — SPF,
DKIM, DMARC, and basic DNS hygiene — and, if you have one, reads a packet
capture to see what TLS version and cipher suite a mail server actually
negotiated in the wild. Everything gets turned into a scored, plain-language
report, with an optional AI-written summary on top.

This is the frontend/reporting piece of **SecureMailScope**, built for SIH
PS 26159 (AI-Assisted Passive Network Forensic Framework for Email
Cryptographic Security).

## What it actually checks

| Check | What it looks at | Where |
|---|---|---|
| **SPF** | TXT record: lookup count vs. the 10-lookup RFC 7208 limit, `all` qualifier strength, duplicate records, deprecated `ptr` mechanism | `src/lib/checks/spf.ts` |
| **DKIM** | Probes ~19 common selector names (`default`, `google`, `selector1`, `s1`, ...) since there's no DNS record that lists selectors; flags revoked/test-mode keys | `src/lib/checks/dkim.ts` |
| **DMARC** | `_dmarc` TXT record: policy strength (`none`/`quarantine`/`reject`), `pct=`, reporting addresses, subdomain policy gaps | `src/lib/checks/dmarc.ts` |
| **Domain** | MX/NS/A record sanity — does it resolve, is there mail routing, is there DNS redundancy | `src/lib/checks/domain.ts` |
| **TLS** | Parses a pcap for TLS handshakes (including STARTTLS, where TLS starts mid-stream after plaintext SMTP/IMAP/POP3 commands) and flags old versions (SSLv3–TLS1.1) and weak ciphers (RC4/3DES/MD5/export-grade) | `src/lib/pcap/`, `src/lib/checks/tls.ts` |

SPF/DKIM/DMARC/Domain checks query **live DNS** via DNS-over-HTTPS (Google's
`dns.google/resolve`, with Cloudflare as a fallback) — the browser has no
raw DNS socket access, so this is the only way to do it client-side.

## How the pcap parsing works (no libraries)

`src/lib/pcap/` is a from-scratch classic-pcap reader:

1. **`pcapParser.ts`** — reads the global header, figures out byte order from
   the magic number, and walks packet records. Only classic `.pcap` is
   supported; `.pcapng` gets a clear error telling you to convert with
   `tshark -F pcap -w out.pcap -r in.pcapng`.
2. **`streamReassembly.ts`** — strips Ethernet/VLAN/raw-IP/Linux-cooked link
   layers, then groups packets into TCP streams by 5-tuple.
3. **`tlsAnalyzer.ts`** — scans each direction of a stream for TLS record
   headers. Critically, it doesn't assume TLS starts at byte 0 — STARTTLS
   protocols (SMTP, IMAP, POP3) send plaintext first, so it scans forward
   for the first offset where a real TLS record chain begins, independently
   in each direction (the two sides aren't even byte-aligned).

This was tested against a real STARTTLS capture where TLS begins 38 bytes
into one direction and 235 bytes into the other — see the chat history in
this project's development for the specific bugs that surfaced and got fixed
(byte-order detection, STARTTLS offset detection).

## AI summary

The "AI summary" tab calls an OpenAI model (`gpt-4o-mini`) through a
**Supabase Edge Function**, so the API key never reaches the browser. Full
setup steps are in [`SETUP_AI_SUMMARY.md`](./SETUP_AI_SUMMARY.md) — short
version:

```bash
supabase login
supabase link --project-ref your-project-ref
supabase secrets set OPENAI_API_KEY=sk-...
supabase functions deploy ai-summary
```

If the OpenAI key isn't set (or the OpenAI call fails for any reason), the
function falls back to a rule-based summary built directly from the scan
results instead of erroring out — you always get *something* in that tab.

## Project structure

```
src/
  types/report.ts          # shared types: Finding, SectionResult, ScanReport, etc.
  lib/
    dns/dnsClient.ts        # DNS-over-HTTPS client (Google + Cloudflare fallback)
    checks/                 # spf.ts, dkim.ts, dmarc.ts, domain.ts, tls.ts
    pcap/                   # pcapParser.ts, streamReassembly.ts, tlsAnalyzer.ts, index.ts
    report/
      buildReport.ts         # orchestrates all checks into one weighted ScanReport
      exportPdf.ts            # jsPDF export
    ai/summarize.ts          # calls the ai-summary edge function
    supabase/client.ts       # Supabase client + isSupabaseConfigured flag
    severityUi.ts            # shared severity -> icon/color/label mappings
  components/
    Sidebar.tsx              # brand, scan form, check navigation
    SidebarScanForm.tsx      # domain input + pcap dropzone + scan button
    FileDropzone.tsx
    MainHeader.tsx           # persistent title + Export PDF button
    OverviewDetail.tsx       # score gauge + top issues across all checks
    SectionDetail.tsx        # full-focus view of one check (SPF/DKIM/DMARC/TLS/Domain)
    AiSummaryPanel.tsx
    TlsStreamTable.tsx       # table of parsed TLS handshakes from a pcap
    ScoreGauge.tsx
    EmptyState.tsx           # first-screen landing content
  App.tsx                    # sidebar + main detail panel layout
supabase/functions/ai-summary/index.ts   # Deno edge function calling OpenAI
```

## Running it

```bash
npm install
cp .env.example .env   # fill in your Supabase project's URL + publishable key
npm run dev
```

| Script | What it does |
|---|---|
| `npm run dev` | Local dev server |
| `npm run build` | Production build (`dist/`) |
| `npm run preview` | Preview the production build locally |
| `npm run lint` | ESLint |
| `npm run typecheck` | `tsc --noEmit` |

### Environment variables

Only two are needed by the frontend, and both go in `.env` (already
gitignored):

```
VITE_SUPABASE_URL=https://your-project-ref.supabase.co
VITE_SUPABASE_ANON_KEY=your-publishable-key
```

**Important:** anything prefixed `VITE_` gets bundled into the public
JavaScript that ships to every visitor's browser. That's fine for the URL
and the publishable/anon key — they're designed to be public. It is **not**
fine for a Supabase service-role/secret key or the OpenAI key — those only
ever go into the edge function's environment via `supabase secrets set`,
never into this `.env` file.

## Known limitations

- **DKIM detection is inherently incomplete.** There's no DNS record that
  lists a domain's selectors, so this probes common names only. A "not
  found" result means "not one of the ~19 we checked," not "definitely no
  DKIM."
- **pcap, not pcapng.** Convert with `tshark -F pcap -w out.pcap -r
  in.pcapng` first if needed.
- **TCP reassembly is sequence-ordered but not gap-aware.** Handles the
  common case (including out-of-order-but-complete captures) but won't
  recover from genuinely missing packets in the middle of a handshake.
- **DNS lookups go through public DoH resolvers** (Google/Cloudflare), so
  results reflect what those resolvers see — usually identical to what a
  mail server would see, but not guaranteed in split-horizon DNS setups.
