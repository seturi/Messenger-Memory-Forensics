#!/usr/bin/env python3
"""Structure-first parser for controlled WhatsApp memory experiments.

The scanner locates address-independent WhatsApp-related record structures
first.  Experiment markers are parsed only after a text field has been reached;
they are ground truth labels, not search signatures.
"""

from __future__ import annotations

import argparse
import csv
import mmap
import os
import re
import struct
import tempfile
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator


SQL_ANCHOR = (
    b"INSERT INTO message (id, chatId, timestamp, text) "
    b"VALUES (?, ?, ?, ?)"
)
COMPACT_ANCHOR = b"\x21\x33\x21\x57"
BLINK_STRING_ANCHOR = b"\x25\x00\x00\x00\x01"
JID_PATTERN = rb"[0-9]{7,20}@(lid|s\.whatsapp\.net|g\.us)"
COMPACT_HEADER_RE = re.compile(
    rb"(?P<message_id>[0-9]{10})"
    rb"(?P<chat_id>" + JID_PATTERN + rb")"
    rb"(?P<timestamp>[0-9]{13}|[0-9]{10})"
)
COMPACT_SEPARATOR_RE = re.compile(
    rb"[\x40-\x5F]\x81[\x00-\xFF]\x06\x00" + re.escape(COMPACT_ANCHOR)
)
MARKER_RE = re.compile(
    r"(?P<state>NML|DEL|EXT)-WHATS-MSG-"
    r"(?P<date>20[0-9]{6})-(?P<clock>[0-9]{6})-"
    r"(?P<sequence>100|0?[1-9][0-9]|0{0,2}[1-9])-END"
)

FIELDS = [
    "source_file", "dump_type", "record_format", "confidence",
    "record_status", "structure_status", "ownership_status", "mapping_status",
    "incomplete_reason", "ownership_reason",
    "structure_offset_dec", "structure_offset_hex", "text_offset_dec",
    "text_offset_hex", "message_id", "chat_id", "message_timestamp",
    "message_timestamp_utc", "message", "validation", "complete", "marker_valid", "state",
    "marker_date", "marker_time", "sequence", "embedded_datetime",
    "structure_hex",
]

SUMMARY_FIELDS = [
    "message", "best_status", "best_structure_status",
    "best_ownership_status", "mapping_statuses",
    "complete_occurrences", "partial_occurrences",
    "marker_valid", "state", "marker_date", "marker_time",
    "sequence", "occurrence_count", "source_count", "source_files",
    "record_formats", "best_confidence", "message_ids", "chat_ids",
    "message_timestamps", "message_variants", "conflicting_fields",
    "evidence_offsets",
]

CONFIDENCE_ORDER = {"MEDIUM": 1, "HIGH": 2}
STATUS_ORDER = {"PARTIAL": 1, "COMPLETE": 2}


@contextmanager
def mapped_input(path: str | os.PathLike[str]):
    with open(path, "rb") as source:
        if os.fstat(source.fileno()).st_size == 0:
            yield b""
        else:
            with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
                yield data


def infer_dump_type(path: str | os.PathLike[str]) -> str:
    name = Path(path).name.lower()
    if "pagefile" in name:
        return "pagefile"
    if "swapfile" in name:
        return "swapfile"
    if name.endswith(".dmp"):
        return "process-memory"
    if "memory" in name or name.endswith(".raw"):
        return "full-memory"
    return "unknown"


def read_varint(data, pos: int, limit: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(10):
        if pos >= limit:
            raise ValueError("truncated varint")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
    raise ValueError("oversized varint")


def read_v8_string(data, pos: int, limit: int) -> tuple[str, int, int]:
    if pos >= limit:
        raise ValueError("missing string tag")
    tag = data[pos]
    pos += 1
    length, pos = read_varint(data, pos, limit)
    if length > 65536 or pos + length > limit:
        raise ValueError("invalid string length")
    raw_start = pos
    raw = bytes(data[pos:pos + length])
    if tag == 0x22:
        value = raw.decode("latin-1")
    elif tag == 0x53:
        value = raw.decode("utf-8")
    elif tag == 0x63:
        if length % 2:
            raise ValueError("odd UTF-16LE string length")
        value = raw.decode("utf-16le")
    else:
        raise ValueError(f"unsupported string tag 0x{tag:02X}")
    return value, pos + length, raw_start


def valid_jid(value: str) -> bool:
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return re.fullmatch(JID_PATTERN, raw) is not None


def valid_timestamp(value: str) -> bool:
    if not value.isdigit() or len(value) not in (10, 13):
        return False
    seconds = int(value) / (1000 if len(value) == 13 else 1)
    return 946684800 <= seconds <= 4102444800  # 2000-01-01 .. 2100-01-01


def timestamp_utc(value: str) -> str:
    if not valid_timestamp(value):
        return ""
    seconds = int(value) / (1000 if len(value) == 13 else 1)
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace("+00:00", "Z")


def marker_fields(text: str) -> dict[str, str]:
    match = MARKER_RE.fullmatch(text)
    if match is None:
        return {
            "marker_valid": "false", "state": "", "marker_date": "",
            "marker_time": "", "sequence": "", "embedded_datetime": "",
        }
    date, clock = match.group("date"), match.group("clock")
    try:
        embedded = datetime.strptime(date + clock, "%Y%m%d%H%M%S").isoformat(
            timespec="seconds"
        )
    except ValueError:
        embedded = ""
    return {
        "marker_valid": "true", "state": match.group("state"),
        "marker_date": date, "marker_time": clock,
        "sequence": match.group("sequence"), "embedded_datetime": embedded,
    }


def parse_sql_at(data, anchor: int, max_record_bytes: int,
                 region_end: int | None = None) -> dict | None:
    limit = min(len(data), anchor + max_record_bytes,
                region_end if region_end is not None else len(data))
    pos = anchor + len(SQL_ANCHOR)
    try:
        message_id, pos, _ = read_v8_string(data, pos, limit)
        chat_id, pos, _ = read_v8_string(data, pos, limit)
        timestamp, pos, _ = read_v8_string(data, pos, limit)
        message, end, text_offset = read_v8_string(data, pos, limit)
    except (UnicodeDecodeError, ValueError):
        return None
    if not message_id.isdigit() or not valid_jid(chat_id) or not valid_timestamp(timestamp):
        return None
    return {
        "record_format": "sqlite-serialized", "confidence": "HIGH",
        "validation": "complete-v8-sql", "complete": True,
        "structure_offset": anchor, "text_offset": text_offset,
        "record_end": end, "message_id": message_id, "chat_id": chat_id,
        "message_timestamp": timestamp, "message": message,
    }


def compact_envelope_start(data, next_anchor: int, lower_bound: int) -> int | None:
    """Locate 0x52 + ULEB128 + 0x06 0x00 framing before the next object."""
    if next_anchor < 2 or bytes(data[next_anchor - 2:next_anchor]) != b"\x06\x00":
        return None
    earliest = max(lower_bound, next_anchor - 14)
    for candidate in range(next_anchor - 3, earliest - 1, -1):
        if data[candidate] != 0x52:
            continue
        try:
            _, end = read_varint(data, candidate + 1, next_anchor - 2)
        except ValueError:
            continue
        if end == next_anchor - 2:
            return candidate
    return None


def utf8_text_end(data, start: int, limit: int) -> int:
    """Walk valid UTF-8 code points until binary framing begins."""
    pos = start
    while pos < limit:
        lead = data[pos]
        if lead < 0x80:
            if lead == 0x7F or (lead < 0x20 and lead not in (0x09, 0x0A, 0x0D)):
                break
            pos += 1
            continue
        if 0xC2 <= lead <= 0xDF:
            width = 2
        elif 0xE0 <= lead <= 0xEF:
            width = 3
        elif 0xF0 <= lead <= 0xF4:
            width = 4
        else:
            break
        if pos + width > limit:
            break
        try:
            bytes(data[pos:pos + width]).decode("utf-8")
        except UnicodeDecodeError:
            break
        pos += width
    return pos


def decode_compact_text(data, text_offset: int, limit: int) -> tuple[str, int, bool]:
    """Decode text and report whether a complete following envelope bounded it."""
    natural_end = utf8_text_end(data, text_offset, limit)
    text_end = natural_end
    complete = False
    search_limit = min(limit, natural_end + 16)
    next_anchor = data.find(COMPACT_ANCHOR, natural_end, search_limit)
    while next_anchor != -1:
        envelope = compact_envelope_start(data, next_anchor, text_offset)
        if envelope is not None and envelope <= natural_end:
            text_end = envelope
            complete = True
            break
        next_anchor = data.find(
            COMPACT_ANCHOR, next_anchor + len(COMPACT_ANCHOR), search_limit
        )
    if text_end <= text_offset:
        raise ValueError("empty compact text")
    return bytes(data[text_offset:text_end]).decode("utf-8"), text_end, complete


def parse_compact_at(data, anchor: int, max_record_bytes: int,
                     region_end: int | None = None) -> dict | None:
    fields_start = anchor + len(COMPACT_ANCHOR)
    limit = min(len(data), fields_start + max_record_bytes,
                region_end if region_end is not None else len(data))
    header = COMPACT_HEADER_RE.match(data, fields_start, limit)
    if header is None:
        return None
    timestamp = header.group("timestamp").decode("ascii")
    if not valid_timestamp(timestamp):
        return None
    text_offset = header.end()
    try:
        message, text_end, complete = decode_compact_text(data, text_offset, limit)
    except (UnicodeDecodeError, ValueError):
        return None
    return {
        "record_format": "compact-object", "confidence": "MEDIUM",
        "validation": "complete-envelope" if complete else "fragment-binary-boundary",
        "complete": complete, "structure_offset": anchor,
        "text_offset": text_offset, "record_end": text_end,
        "message_id": header.group("message_id").decode("ascii"),
        "chat_id": header.group("chat_id").decode("ascii"),
        "message_timestamp": timestamp, "message": message,
    }


def parse_blink_string_at(data, length_anchor: int,
                          region_end: int | None = None) -> dict | None:
    """Parse a validated Blink/StringImpl copy of a controlled message text."""
    header = length_anchor - 8
    if header < 0:
        return None
    limit = min(len(data), region_end if region_end is not None else len(data))
    if header + 16 > limit:
        return None
    prefix, refcount, length, hash_flags = struct.unpack_from("<IIII", data, header)
    if prefix not in (0, 1) or not 0 < refcount < 1_000_000:
        return None
    if length != 37 or hash_flags & 0xFF != 1:
        return None
    text_offset, text_end = header + 16, header + 16 + length
    if text_end > limit:
        return None
    try:
        message = bytes(data[text_offset:text_end]).decode("ascii")
    except UnicodeDecodeError:
        return None
    if MARKER_RE.fullmatch(message) is None:
        return None
    return {
        "record_format": "blink-stringimpl", "confidence": "MEDIUM",
        "validation": "complete-stringimpl", "complete": False,
        "structure_status": "COMPLETE_STRING",
        "structure_offset": header, "text_offset": text_offset,
        "record_end": text_end, "message_id": "", "chat_id": "",
        "message_timestamp": "", "message": message,
    }


def _iter_anchor_positions(data, scan_chunk_bytes: int = 256 << 20,
                           include_string_objects: bool = False):
    """Find record and optional string-object anchors in one local file pass."""
    total = len(data)
    anchors = [("sql", SQL_ANCHOR), ("compact", COMPACT_ANCHOR)]
    if include_string_objects:
        anchors.append(("blink", BLINK_STRING_ANCHOR))
    for chunk_start in range(0, total, scan_chunk_bytes):
        chunk_end = min(total, chunk_start + scan_chunk_bytes)
        found = []
        for kind, token in anchors:
            search_end = min(total, chunk_end + len(token) - 1)
            position = chunk_start
            while True:
                offset = data.find(token, position, search_end)
                if offset < 0 or offset >= chunk_end:
                    break
                found.append((offset, kind))
                position = offset + len(token)
        yield from sorted(found)


def iter_structures(data, max_record_bytes: int = 65536,
                    include_fragments: bool = False, boundary=None) -> Iterator[dict]:
    if max_record_bytes < 256:
        raise ValueError("max_record_bytes must be at least 256")
    for anchor, kind in _iter_anchor_positions(
            data, include_string_objects=include_fragments):
        region_end = boundary(anchor) if boundary is not None else len(data)
        if region_end <= anchor:
            continue
        if kind == "sql":
            record = parse_sql_at(data, anchor, max_record_bytes, region_end)
        elif kind == "compact":
            record = parse_compact_at(data, anchor, max_record_bytes, region_end)
        else:
            record = parse_blink_string_at(data, anchor, region_end)
        if record is not None and (record["complete"] or include_fragments):
            yield record


def iter_records(data, source_file: str, max_record_bytes: int = 65536,
                 structure_context: int = 256,
                 include_fragments: bool = False) -> Iterator[dict]:
    dump_type = infer_dump_type(source_file)
    dump = None
    if bytes(data[:4]) == b"MDMP":
        try:
            from .minidump_info import MiniDump
        except ImportError:
            from minidump_info import MiniDump
        dump = MiniDump(data)
    boundary = dump.boundary if dump is not None else lambda _offset: len(data)
    source = str(Path(source_file).resolve())
    for parsed in iter_structures(data, max_record_bytes, include_fragments, boundary):
        start = parsed["structure_offset"]
        context_end = min(boundary(start), parsed["record_end"] + structure_context)
        context = bytes(data[start:context_end])
        row = {
            "source_file": source, "dump_type": dump_type,
            "record_format": parsed["record_format"],
            "confidence": parsed["confidence"],
            "record_status": "COMPLETE" if parsed["complete"] else "PARTIAL",
            "structure_status": parsed.get(
                "structure_status",
                "COMPLETE_RECORD" if parsed["complete"] else "PARTIAL_RECORD",
            ),
            "ownership_status": (
                ("UNLINKED" if dump is not None else "UNVERIFIABLE")
                if parsed["record_format"] == "blink-stringimpl"
                else "NOT_REQUIRED"
            ),
            "mapping_status": "MINIDUMP_VA" if dump is not None else "FLAT_BYTES",
            "incomplete_reason": (
                "" if parsed["complete"]
                else (
                    "message_record_fields_unlinked"
                    if parsed["record_format"] == "blink-stringimpl"
                    else "missing_complete_next_envelope"
                )
            ),
            "ownership_reason": (
                (
                    "record_link_not_found" if dump is not None
                    else "record_link_not_testable_without_virtual_mapping"
                )
                if parsed["record_format"] == "blink-stringimpl" else ""
            ),
            "structure_offset_dec": start,
            "structure_offset_hex": f"0x{start:X}",
            "text_offset_dec": parsed["text_offset"],
            "text_offset_hex": f"0x{parsed['text_offset']:X}",
            "message_id": parsed["message_id"], "chat_id": parsed["chat_id"],
            "message_timestamp": parsed["message_timestamp"],
            "message_timestamp_utc": timestamp_utc(parsed["message_timestamp"]),
            "message": parsed["message"], "validation": parsed["validation"],
            "complete": str(parsed["complete"]).lower(),
            "structure_hex": context.hex(),
        }
        row.update(marker_fields(parsed["message"]))
        yield row

def collect_inputs(inputs: Iterable[str], recursive: bool,
                   excluded: set[Path]) -> list[Path]:
    files: list[Path] = []
    evidence_suffixes = {".raw", ".dmp", ".sys", ".bin"}
    for value in inputs:
        path = Path(value)
        if path.is_file():
            files.append(path.resolve())
        elif path.is_dir():
            iterator = path.rglob("*") if recursive else path.glob("*")
            files.extend(
                candidate.resolve() for candidate in iterator
                if candidate.is_file() and candidate.suffix.lower() in evidence_suffixes
            )
        else:
            raise FileNotFoundError(value)
    return sorted(set(files) - excluded, key=lambda item: str(item).lower())


def write_csv_atomic(rows: Iterable[dict], fields: list[str], output: Path) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".whatsapp-structure-", suffix=".csv", dir=output.parent
    )
    count = 0
    try:
        with os.fdopen(descriptor, "w", newline="", encoding="utf-8-sig") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
                count += 1
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return count


def summarize(rows: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        key = ("marker", row["message"]) if row.get("marker_valid") == "true" else (
            "id", row["message_id"]
        )
        groups[key].append(row)
    output = []
    for group_key in sorted(groups):
        items = groups[group_key]
        first = items[0]
        messages = {item["message"] for item in items}
        sources = sorted({item["source_file"] for item in items})
        offsets = sorted(
            f"{Path(item['source_file']).name}@{item['structure_offset_hex']}"
            for item in items
        )
        chats = {item["chat_id"] for item in items if item.get("chat_id")}
        timestamps = {
            item["message_timestamp"] for item in items if item.get("message_timestamp")
        }
        conflicts = []
        if len(messages) > 1:
            conflicts.append("message")
        if len(chats) > 1:
            conflicts.append("chat_id")
        if len(timestamps) > 1:
            conflicts.append("message_timestamp")
        best = max(items, key=lambda x: (
            STATUS_ORDER.get(x.get("record_status", "COMPLETE"), 0),
            CONFIDENCE_ORDER.get(x.get("confidence", "MEDIUM"), 0),
        ))
        output.append({
            "message": first["message"],
            "best_status": best.get("record_status", "COMPLETE"),
            "best_structure_status": best.get(
                "structure_status",
                "COMPLETE_RECORD" if best.get("record_status", "COMPLETE") == "COMPLETE"
                else "PARTIAL_RECORD",
            ),
            "best_ownership_status": best.get("ownership_status", "NOT_REQUIRED"),
            "mapping_statuses": " | ".join(sorted({
                x.get(
                    "mapping_status",
                    "MINIDUMP_VA" if infer_dump_type(x["source_file"]) == "process-memory"
                    else "FLAT_BYTES",
                )
                for x in items
            })),
            "complete_occurrences": sum(
                x.get("record_status", "COMPLETE") == "COMPLETE" for x in items
            ),
            "partial_occurrences": sum(
                x.get("record_status", "COMPLETE") == "PARTIAL" for x in items
            ),
            "marker_valid": first["marker_valid"],
            "state": first["state"], "marker_date": first["marker_date"],
            "marker_time": first["marker_time"], "sequence": first["sequence"],
            "occurrence_count": len(items), "source_count": len(sources),
            "source_files": " | ".join(sources),
            "record_formats": " | ".join(sorted({x["record_format"] for x in items})),
            "best_confidence": max(
                (x["confidence"] for x in items), key=CONFIDENCE_ORDER.get
            ),
            "message_ids": " | ".join(sorted({
                x["message_id"] for x in items if x.get("message_id")
            })),
            "chat_ids": " | ".join(sorted({
                x["chat_id"] for x in items if x.get("chat_id")
            })),
            "message_timestamps": " | ".join(sorted(timestamps)),
            "message_variants": " | ".join(sorted(messages)),
            "conflicting_fields": " | ".join(conflicts),
            "evidence_offsets": " | ".join(offsets),
        })
    return output


def merge_result_csvs(paths: Iterable[str | os.PathLike[str]], output: Path) -> dict:
    rows = []
    for path in sorted({Path(value).resolve() for value in paths}):
        if path == output.resolve():
            raise ValueError("output must not overwrite an input result")
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            required = {"message_id", "message", "source_file", "structure_offset_hex"}
            if not required.issubset(reader.fieldnames or []):
                raise ValueError(f"not a WhatsApp structure CSV: {path}")
            rows.extend(reader)
    summaries = summarize(rows)
    write_csv_atomic(summaries, SUMMARY_FIELDS, output)
    return {
        "unique_messages": len(summaries),
        "input_rows": len(rows),
        "occurrences": len(rows),
        "complete_occurrences": sum(
            row.get("record_status", "COMPLETE") == "COMPLETE" for row in rows
        ),
        "partial_occurrences": sum(
            row.get("record_status", "COMPLETE") == "PARTIAL" for row in rows
        ),
        "conflicting_messages": sum(bool(row["conflicting_fields"]) for row in summaries),
        "output_file": str(output.resolve()),
    }



def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse address-independent WhatsApp message structures"
    )
    parser.add_argument("inputs", nargs="+", help="Evidence files or directories")
    parser.add_argument("-o", "--output", required=True, help="Occurrence CSV")
    parser.add_argument("--unique-output", help="Optional message summary CSV")
    parser.add_argument("--recursive", action="store_true")
    parser.add_argument("--max-record-bytes", type=int, default=65536)
    parser.add_argument("--structure-context", type=int, default=256)
    parser.add_argument("--evidence", action="store_true",
                        help="Include incomplete compact boundary candidates")
    args = parser.parse_args()
    if args.structure_context < 0:
        parser.error("structure-context must not be negative")
    try:
        output = Path(args.output).resolve()
        unique = Path(args.unique_output).resolve() if args.unique_output else None
        files = collect_inputs(args.inputs, args.recursive, {output, unique})
        if not files:
            raise ValueError("no evidence files")
        rows: list[dict] = []
        for path in files:
            print(f"[scan] {path}", flush=True)
            with mapped_input(path) as data:
                found = list(iter_records(
                    data, str(path), args.max_record_bytes, args.structure_context,
                    args.evidence
                ))
            rows.extend(found)
            print(f"[found] {path.name}: {len(found)}", flush=True)
        write_csv_atomic(rows, FIELDS, output)
        print(f"[ok] structures={len(rows)} -> {output}")
        if unique is not None:
            unique_rows = summarize(rows)
            write_csv_atomic(unique_rows, SUMMARY_FIELDS, unique)
            print(f"[ok] unique_messages={len(unique_rows)} -> {unique}")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
