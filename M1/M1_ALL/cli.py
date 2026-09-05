"""Command line entry point for SecureMailScope M1."""
from __future__ import annotations
import argparse, json, sys
from .fields_config import CANDIDATE_FIELDS, verify_fields
from .pipeline import build_report
from .tshark import TSharkError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="securemailscope-m1", description="Extract network/email/TLS evidence from a PCAP with TShark.")
    sub = parser.add_subparsers(dest="command", required=True)
    extract = sub.add_parser("extract", help="extract structured JSON evidence")
    extract.add_argument("pcap")
    extract.add_argument("-o", "--output", help="output JSON file; stdout when omitted")
    extract.add_argument("--tshark", default="tshark")
    verify = sub.add_parser("verify-fields", help="verify candidate fields against installed TShark")
    verify.add_argument("--tshark", default="tshark")
    args = parser.parse_args(argv)
    if args.command == "verify-fields":
        result = verify_fields(args.tshark)
        print(json.dumps({"tshark_version": result.tshark_version, "fields": result.available, "field_lines": result.raw_field_lines, "error": result.error}, indent=2))
        return 0 if result.tshark_version else 2
    try:
        report = build_report(args.pcap, args.tshark)
    except TSharkError as exc:
        print(f"error: {exc}", file=sys.stderr); return 2
    output = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(output)
        except OSError as exc:
            print(f"error: could not write output: {exc}", file=sys.stderr)
            return 2
    else: print(output, end="")
    return 0

if __name__ == "__main__": raise SystemExit(main())
