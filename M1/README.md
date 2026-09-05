# SecureMailScope M1 — PCAP / Network Evidence Extraction

M1 is a Python + TShark evidence-extraction module for PCAP and PCAPNG files. It reports observed SMTP, IMAP, POP3, TCP stream, STARTTLS, TLS handshake, certificate, and capture-quality evidence. It does **not** score risk, make security judgments, run offensive scans, or infer that an unobserved event did not happen.

## Project structure

```text
securemailscope-m1/
├── pyproject.toml
├── requirements.txt
├── README.md
├── schemas/evidence.schema.json
├── examples/sample_evidence.json
├── scripts/verify_tshark_fields.sh
├── securemailscope_m1/
│   ├── __init__.py
│   ├── analyze.py
│   ├── certificates.py
│   ├── cli.py
│   ├── extract.py
│   ├── fields_config.py
│   ├── models.py
│   ├── parsing.py
│   ├── pipeline.py
│   └── tshark.py
└── tests/test_core.py
```

## Install

Install TShark using the operating system package manager, then install Python dependencies:

```bash
sudo apt-get update
sudo apt-get install -y tshark
cd securemailscope-m1
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

No real email credentials, account, or SMTP server is required.

## Verify TShark fields

The installed TShark/Wireshark version is authoritative. Run:

```bash
./scripts/verify_tshark_fields.sh
# or
securemailscope-m1 verify-fields
# inspect all fields directly
tshark -G fields | less
# inspect version
tshark --version
```

On Windows PowerShell, use `securemailscope-m1 verify-fields` or
`python -m securemailscope_m1.cli verify-fields`; the `.sh` wrapper requires a
Bash environment.

The report records availability of every candidate field. Missing fields are not silently treated as present. Field names are centralized in `securemailscope_m1/fields_config.py`.

## CLI

```bash
securemailscope-m1 extract capture.pcapng
securemailscope-m1 extract capture.pcap -o evidence.json
securemailscope-m1 extract capture.pcap --tshark /usr/bin/tshark -o evidence.json
```

The command writes JSON to stdout unless `-o` is supplied. It returns exit code `2` for missing captures, missing TShark, TShark failures, or malformed TShark JSON.

## Tests and known captures

Run deterministic unit tests:

```bash
python -m unittest discover -s tests -v
```

For an official/known capture, run the CLI and validate the output against the schema:

```bash
securemailscope-m1 extract /path/to/known-capture.pcapng -o evidence.json
python - <<'PY'
import json
from jsonschema import validate
with open('evidence.json') as f: evidence=json.load(f)
with open('schemas/evidence.schema.json') as f: schema=json.load(f)
validate(evidence, schema)
print('schema valid')
PY
```

`jsonschema` is optional and can be installed with `python -m pip install jsonschema`. Official captures are preferred; local SMTP generation is optional and this project never requires the deprecated `python3 -m smtpd` module.

## Execution flow

`cli.py` parses the command and calls `pipeline.build_report`. `tshark.py` first verifies candidate field names with `tshark -G fields`, then safely invokes TShark with an argument list and parses its JSON. `extract.py` normalizes packet layers while preserving frame order, groups TCP stream evidence, and identifies ordered STARTTLS events. `analyze.py` separately reports TLS stages and conservative capture-quality indicators. `certificates.py` extracts raw DER candidates and parses them with `cryptography`, distinguishing `self_issued` from cryptographically verified `self_signed`. `pipeline.py` combines all results into one JSON document.

The report also contains an additive `handoff` object with `network`, `tls`, and `m2` sections for downstream modules. The `m2` section contains `domain`, `spf`, `dkim`, `dmarc`, and `risk` placeholders as `null`; M1 does not populate them. M2 owns DNS lookups, analysis, risk scoring, and live reachability checks. The original detailed evidence sections remain unchanged for forensic use.

STARTTLS states are intentionally separate: `advertised`, `attempted`, `acknowledged_or_accepted`, and `tls_followed`. A command alone never means negotiation succeeded. A ServerHello alone never means a handshake completed. TLS 1.3 is reported only from observed version/supported-version text, never from cipher-suite names.

## Semantics and limitations

`NOT_FOUND` means no matching evidence was observed. `UNKNOWN` means the evidence or tool capability was insufficient to determine a property. `INSUFFICIENT_EVIDENCE` is used where a negative conclusion would be unsafe, such as no TLS handshake in a truncated or mid-session capture.

`tcp.completeness` is retained as an observed value only. Its bitmask interpretation is version-sensitive and must be verified against the installed Wireshark/TShark documentation; capture-quality output is conservative heuristic evidence and never proof of complete TCP reassembly.

Certificate parsing returns raw DER and `null` for unsupported or unavailable self-signature verification. A matching subject and issuer is `self_issued`; `self_signed` is true only after supported public-key verification succeeds.

## Debugging checklist

1. Run `tshark --version` and `securemailscope-m1 verify-fields`.
2. Confirm the file is readable: `capinfos capture.pcapng`.
3. Check basic decoding: `tshark -n -r capture.pcapng -c 10`.
4. Check protocol filters manually: `tshark -n -r capture.pcapng -Y 'smtp || imap || pop || tls'`.
5. If fields are missing, use the exact names printed by `tshark -G fields`; update the central registry rather than guessing.
6. If a capture is truncated, expect `INSUFFICIENT_EVIDENCE` or an incomplete handshake rather than a negative TLS claim.
7. If certificate parsing fails, preserve the `der_hex` and inspect whether the field contained a complete DER certificate rather than a truncated or non-certificate value.
8. For multiple TLS records in one packet, inspect the JSON layer lists; the extractor recursively preserves scalar/list values instead of overwriting duplicate fields.
9. Never use `shell=True`; all subprocesses in this code use argument arrays.
