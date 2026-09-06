# Setting up the AI summary feature

The "AI summary" tab calls an OpenAI model to write a plain-language summary
of the scan results. The OpenAI key lives in a Supabase Edge Function, never
in the browser bundle.

## 1. Link the project to Supabase

```bash
npm install -g supabase
supabase login
supabase link --project-ref your-project-ref
```

## 2. Set the OpenAI key as a function secret

```bash
supabase secrets set OPENAI_API_KEY=sk-...
```

## 3. Deploy the edge function

```bash
supabase functions deploy ai-summary
```

## 4. Point the frontend at your Supabase project

Copy `.env.example` to `.env` and fill in your project's URL and anon key
(Supabase dashboard -> Project Settings -> API):

```bash
cp .env.example .env
```

```
VITE_SUPABASE_URL=https://your-project-ref.supabase.co
VITE_SUPABASE_ANON_KEY=your-anon-public-key
```

Restart `npm run dev` after editing `.env` — Vite only reads it at startup.

## What it sends

Clicking "Generate summary" sends the report's scores, severities, and
finding text (SPF/DKIM/DMARC/TLS/Domain) to the edge function, which forwards
a condensed version to `gpt-4o-mini` and returns the model's summary. No pcap
bytes or raw DNS records are sent — just the already-computed findings.

## If it's not configured

If `OPENAI_API_KEY` is not set on the function, it returns a short summary
based directly on the scan results instead of failing. Add the secret to enable
the LLM-generated version.
