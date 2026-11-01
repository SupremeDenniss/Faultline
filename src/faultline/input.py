"""Bounded parsing of local JSON, JSON arrays, and JSON Lines."""

from __future__ import annotations

import json
from pathlib import Path

from faultline.models import InputRecord

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_RECORD_BYTES = 256 * 1024
MAX_RECORDS = 10_000


class InputError(ValueError):
    """The input file cannot be processed safely."""


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON constant {value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _loads(value: str) -> object:
    return json.loads(value, parse_constant=_reject_constant, object_pairs_hook=_unique_object)


def read_records(path: Path) -> list[InputRecord]:
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise InputError(f"cannot read input file: {exc.strerror or exc}") from exc
    if len(data) > MAX_FILE_BYTES:
        raise InputError(f"input file exceeds {MAX_FILE_BYTES} bytes")
    try:
        content = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InputError("input file must be UTF-8") from exc
    if not content.strip():
        raise InputError("input file is empty")

    try:
        whole = _loads(content)
    except (json.JSONDecodeError, ValueError, RecursionError):
        records = []
        for number, line in enumerate(content.splitlines(), 1):
            if not line.strip():
                continue
            if len(records) >= MAX_RECORDS:
                raise InputError(f"input contains more than {MAX_RECORDS} records") from None
            if len(line.encode("utf-8")) > MAX_RECORD_BYTES:
                records.append(InputRecord(f"line {number}", None, "record exceeds 256 KiB"))
                continue
            try:
                records.append(InputRecord(f"line {number}", _loads(line)))
            except (json.JSONDecodeError, ValueError, RecursionError):
                records.append(InputRecord(f"line {number}", None, "invalid JSON"))
        return records

    values = whole if isinstance(whole, list) else [whole]
    if len(values) > MAX_RECORDS:
        raise InputError(f"input contains more than {MAX_RECORDS} records")
    records = []
    for index, value in enumerate(values, 1):
        try:
            size = len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))
        except (ValueError, RecursionError, UnicodeEncodeError):
            records.append(InputRecord(f"record {index}", None, "invalid JSON structure"))
            continue
        error = "record exceeds 256 KiB" if size > MAX_RECORD_BYTES else None
        records.append(InputRecord(f"record {index}", value, error))
    return records
