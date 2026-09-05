"""Small, JSON-friendly evidence model helpers."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from typing import Any

NOT_FOUND = "NOT_FOUND"
UNKNOWN = "UNKNOWN"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

@dataclass
class Evidence:
    status: str = NOT_FOUND
    details: dict[str, Any] = field(default_factory=dict)

@dataclass
class PacketRecord:
    frame_number: int
    timestamp: float | None = None
    length: int | None = None
    protocols: list[str] = field(default_factory=list)
    src: str | None = None
    dst: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_stream: int | None = None
    tcp_flags: str | None = None
    tcp_payload_length: int | None = None
    layers: dict[str, Any] = field(default_factory=dict)


def clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v) for v in value]
    return value


def to_dict(obj: Any) -> dict[str, Any]:
    return clean(asdict(obj)) if hasattr(obj, "__dataclass_fields__") else clean(obj)
