"""Defensive helpers for TShark's sometimes scalar/sometimes-list JSON values."""
from __future__ import annotations
from typing import Any


def first(value: Any, default: Any = None) -> Any:
    if isinstance(value, list):
        return first(value[0], default) if value else default
    return value if value is not None else default


def all_values(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        result: list[Any] = []
        for item in value:
            result.extend(all_values(item))
        return result
    return [value]


def as_int(value: Any) -> int | None:
    value = first(value)
    try:
        if isinstance(value, str) and value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except (TypeError, ValueError):
        return None


def as_float(value: Any) -> float | None:
    try:
        return float(first(value))
    except (TypeError, ValueError):
        return None


def layer(packet: dict[str, Any], name: str) -> dict[str, Any]:
    layers = packet.get("_source", {}).get("layers", {})
    value = layers.get(name, {})
    return value if isinstance(value, dict) else {name: value}


def field(packet: dict[str, Any], name: str, default: Any = None) -> Any:
    return layer(packet, name.split(".")[0]).get(name, default)


def nested_values(value: Any, name: str) -> list[Any]:
    if isinstance(value, dict):
        result: list[Any] = []
        if name in value:
            result.extend(all_values(value[name]))
        for child in value.values():
            result.extend(nested_values(child, name))
        return result
    if isinstance(value, list):
        result: list[Any] = []
        for child in value:
            result.extend(nested_values(child, name))
        return result
    return []
