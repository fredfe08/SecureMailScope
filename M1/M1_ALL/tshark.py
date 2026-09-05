"""Safe TShark invocation and JSON packet ingestion."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
from typing import Any
from .fields_config import FieldVerification, verify_fields, tshark_version

class TSharkError(RuntimeError):
    pass


def _merge_certificate_fields(cmd: list[str], packets: list[dict[str, Any]]) -> None:
    # Only carry over the binary and "-r <path>" from cmd. Any caller-supplied
    # "-Y <display_filter>" must NOT be copied here: this pass needs its own
    # "-Y tls.handshake.certificate" filter, and a second "-Y" on the command
    # line would silently override it (or make TShark reject the invocation).
    r_index = cmd.index("-r")
    read_args = cmd[r_index:r_index + 2]
    field_cmd = [*cmd[:1], "-T", "json", "-e", "frame.number", "-e", "tls.handshake.certificate", "-Y", "tls.handshake.certificate", *read_args]
    try:
        proc = subprocess.run(field_cmd, text=True, capture_output=True, check=False)
        if proc.returncode != 0:
            return
        rows = json.loads(proc.stdout or "[]")
    except (OSError, json.JSONDecodeError):
        return
    by_frame = {str(row.get("_source", {}).get("layers", {}).get("frame.number", [None])[0]): row for row in rows}
    for packet in packets:
        layers = packet.setdefault("_source", {}).setdefault("layers", {})
        frame_number = str(layers.get("frame", {}).get("frame.number", ""))
        row = by_frame.get(frame_number)
        if row:
            values = row.get("_source", {}).get("layers", {}).get("tls.handshake.certificate")
            layers.setdefault("tls", {})["tls.handshake.certificate"] = values


def run_tshark(pcap: str | Path, binary: str = "tshark", display_filter: str | None = None) -> tuple[list[dict[str, Any]], FieldVerification]:
    path = Path(pcap)
    if not path.is_file():
        raise TSharkError(f"capture does not exist: {path}")
    verification = verify_fields(binary)
    if verification.tshark_version is None:
        raise TSharkError(verification.error or "TShark is unavailable")
    cmd = [binary, "-n", "-T", "json", "-r", str(path)]
    if display_filter:
        cmd.extend(["-Y", display_filter])
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    except OSError as exc:
        raise TSharkError(str(exc)) from exc
    if proc.returncode != 0:
        message = proc.stderr.strip() or "TShark failed without an error message"
        raise TSharkError(message)
    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise TSharkError(f"TShark returned invalid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise TSharkError("TShark JSON root was not a packet list")
    if verification.available.get("tls.handshake.certificate"):
        _merge_certificate_fields(cmd, data)
    return data, verification


def capture_summary(pcap: str | Path, binary: str = "tshark") -> dict[str, Any]:
    path = Path(pcap)
    if not path.is_file():
        raise TSharkError(f"capture does not exist: {path}")
    cmd = [binary, "-n", "-q", "-z", "io,phs", "-r", str(path)]
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, check=False)
    except OSError as exc:
        raise TSharkError(str(exc)) from exc
    return {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
