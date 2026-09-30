#!/usr/bin/env python3
"""Telegram Desktop memory parser for controlled message-recovery experiments.

Distinguishes Telegram-owned Qt QStrings, unlinked QString copies, and bare
marker strings. Offsets always refer to bytes in the input evidence file.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import mmap
import os
import re
import struct
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

try:
    from .minidump_info import MiniDump
except ImportError:
    from minidump_info import MiniDump


STATES = ("NML", "DEL", "EXT")
ASCII_ANCHOR = b"-TELE-MSG-"
ASCII_PATTERN = re.compile(
    rb"(?P<state>NML|DEL|EXT)-TELE-MSG-"
    rb"(?P<date>[0-9]{8})-(?P<clock>[0-9]{6})-"
    rb"(?P<sequence>100|0?[1-9][0-9]|0{0,2}[1-9])-END"
)


def _u(value: bytes) -> bytes:
    return b"".join(bytes((byte, 0)) for byte in value)


D16 = rb"[0-9]\x00"
UTF16_ANCHOR = _u(ASCII_ANCHOR)
UTF16_PATTERN = re.compile(
    rb"(?P<state>" + b"|".join(_u(x.encode()) for x in STATES) + rb")"
    + _u(b"-TELE-MSG-")
    + rb"(?P<date>(?:" + D16 + rb"){8})" + _u(b"-")
    + rb"(?P<clock>(?:" + D16 + rb"){6})" + _u(b"-")
    + rb"(?P<sequence>(?:" + _u(b"100")
    + rb"|(?:" + _u(b"0") + rb")?[1-9]\x00" + D16
    + rb"|(?:" + _u(b"0") + rb"){0,2}[1-9]\x00))"
    + _u(b"-END")
)
TEXT_MARKER_RE = re.compile(
    r"(?P<state>NML|DEL|EXT)-TELE-MSG-"
    r"(?P<date>[0-9]{8})-(?P<clock>[0-9]{6})-"
    r"(?P<sequence>100|0?[1-9][0-9]|0{0,2}[1-9])-END"
)

STATUS_RANK = {"MARKER_ONLY": 0, "PARTIAL": 1, "COMPLETE": 2}
CONFIDENCE_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

FIELDS = [
    "source_file", "dump_type", "record_format", "record_status", "confidence",
    "structure_status", "ownership_status", "mapping_status",
    "incomplete_reason", "ownership_reason",
    "structure_offset_dec", "structure_offset_hex",
    "text_offset_dec", "text_offset_hex", "record_end_dec", "record_end_hex",
    "owner_offset_dec", "owner_offset_hex", "owner_virtual_address",
    "qstring_virtual_address", "message_id", "chat_id", "message_timestamp",
    "message", "container_text", "marker_valid", "state", "marker_date",
    "marker_time", "sequence", "embedded_datetime", "encoding",
    "qstring_refcount", "qstring_size", "qstring_capacity",
    "qstring_capacity_reserved", "terminator_valid", "evidence_hex",
]
SUMMARY_FIELDS = [
    "message", "best_status", "best_confidence", "best_structure_status",
    "best_ownership_status", "state", "marker_date",
    "marker_time", "sequence", "embedded_datetime", "occurrence_count",
    "complete_occurrences", "partial_occurrences", "marker_only_occurrences",
    "source_count", "source_files", "record_formats", "encodings",
    "mapping_statuses", "ownership_statuses",
    "incomplete_reasons", "ownership_reasons", "evidence_offsets",
]


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


def marker_fields(marker: str) -> dict[str, str]:
    match = TEXT_MARKER_RE.fullmatch(marker)
    if match is None:
        raise ValueError("internal marker mismatch")
    date, clock = match["date"], match["clock"]
    embedded = ""
    try:
        embedded = datetime.strptime(date + clock, "%Y%m%d%H%M%S").isoformat(
            timespec="seconds"
        )
    except ValueError:
        pass
    return {
        "marker_valid": "true", "state": match["state"],
        "marker_date": date, "marker_time": clock,
        "sequence": match["sequence"], "embedded_datetime": embedded,
    }


def iter_markers(data, scan_chunk_bytes: int = 256 << 20) -> Iterator[dict]:
    """Search both encodings while each mapped file region is resident."""
    scanners = (
        ("ascii", ASCII_ANCHOR, ASCII_PATTERN, 3),
        ("utf-16le", UTF16_ANCHOR, UTF16_PATTERN, 6),
    )
    total = len(data)
    for chunk_start in range(0, total, scan_chunk_bytes):
        chunk_end = min(total, chunk_start + scan_chunk_bytes)
        found = []
        for encoding, anchor, pattern, state_width in scanners:
            search_end = min(total, chunk_end + len(anchor) - 1)
            position = chunk_start
            while True:
                anchor_at = data.find(anchor, position, search_end)
                if anchor_at < 0 or anchor_at >= chunk_end:
                    break
                position = anchor_at + len(anchor)
                start = anchor_at - state_width
                if start < 0:
                    continue
                match = pattern.match(data, start)
                if match is None:
                    continue
                marker = bytes(match.group(0)).decode(encoding)
                found.append({
                    "offset": start, "end": match.end(), "encoding": encoding,
                    "message": marker, **marker_fields(marker),
                })
        yield from sorted(found, key=lambda row: row["offset"])


def parse_qstring(data, marker: dict, boundary: int,
                  max_text_chars: int = 4096) -> dict | None:
    if marker["encoding"] != "utf-16le" or marker["offset"] < 24:
        return None
    header = marker["offset"] - 24
    if header + 24 > boundary:
        return None
    refcount, size, allocation = struct.unpack_from("<iiI", data, header)
    data_offset, = struct.unpack_from("<q", data, header + 16)
    capacity = allocation & 0x7FFFFFFF
    reserved = bool(allocation & 0x80000000)
    if (
        data_offset != 24
        or refcount < -1 or refcount > 1_000_000
        or size < len(marker["message"]) or size > max_text_chars
        or capacity < size or capacity > 16_777_216
    ):
        return None
    text_start = header + data_offset
    text_end = text_start + size * 2
    if text_start != marker["offset"] or text_end + 2 > boundary:
        return None
    try:
        container = bytes(data[text_start:text_end]).decode("utf-16le")
    except UnicodeDecodeError:
        return None
    if not container.startswith(marker["message"]):
        return None
    if bytes(data[text_end:text_end + 2]) != b"\x00\x00":
        return None
    return {
        **marker, "structure_offset": header, "record_end": text_end + 2,
        "container_text": container, "qstring_refcount": refcount,
        "qstring_size": size, "qstring_capacity": capacity,
        "qstring_capacity_reserved": reserved, "terminator_valid": True,
        "exact_qstring": container == marker["message"],
    }


def _va_to_file(dump: MiniDump, address: int) -> int | None:
    index = bisect.bisect_right(dump.starts, address) - 1
    if index < 0:
        return None
    start, end, file_offset = dump.ranges[index]
    return file_offset + address - start if start <= address < end else None


def find_owner_links(data, dump: MiniDump,
                     qstrings: dict[int, dict]) -> dict[int, tuple[int, int]]:
    """Learn a repeated owner layout in this dump; no address is hard-coded."""
    exact = sorted(
        (row for row in qstrings.values() if row["exact_qstring"]),
        key=lambda row: row["structure_offset"], reverse=True,
    )
    best: dict[int, tuple[int, int]] = {}
    for seed in exact[:24]:
        qva = dump.virtual_address(seed["structure_offset"])
        if qva is None:
            continue
        needle = struct.pack("<Q", qva)
        reference = data.find(needle)
        while reference >= 32:
            if dump.file_region(reference) is not None:
                signature = bytes(data[reference - 32:reference])
                links: dict[int, tuple[int, int]] = {}
                position = 0
                while True:
                    owner = data.find(signature, position)
                    if owner < 0:
                        break
                    pointer_at = owner + 32
                    if pointer_at + 8 <= len(data):
                        target_va, = struct.unpack_from("<Q", data, pointer_at)
                        target_file = _va_to_file(dump, target_va)
                        if target_file in qstrings:
                            links[target_file] = (
                                owner, dump.virtual_address(owner) or 0
                            )
                    position = owner + 1
                if len(links) >= 3 and len(links) > len(best):
                    best = links
            reference = data.find(needle, reference + 1)
        if best:
            break
    return best


def normalize_semantics(row: dict) -> dict:
    """Separate record integrity from owner-link and address-map evidence."""
    row = dict(row)
    mapping = "MINIDUMP_VA" if row.get("dump_type") == "process-memory" else "FLAT_BYTES"
    fmt = row.get("record_format", "")
    reason = row.get("incomplete_reason", "")
    has_owner = bool(row.get("owner_offset_dec")) or fmt == "telegram-owner-qstring"
    exact_qstring = (
        row.get("structure_status") == "COMPLETE_QSTRING"
        or (
            fmt == "qt-qstring"
            and row.get("terminator_valid") in (True, "true")
            and row.get("container_text") == row.get("message")
        )
    )
    row["mapping_status"] = mapping
    if has_owner:
        row.update(
            record_status="COMPLETE", confidence="HIGH",
            structure_status="COMPLETE_QSTRING", ownership_status="LINKED",
            incomplete_reason="", ownership_reason="",
        )
    elif fmt == "qt-qstring" and (reason == "unlinked_qstring_copy" or exact_qstring):
        ownership = "UNLINKED" if mapping == "MINIDUMP_VA" else "UNVERIFIABLE"
        ownership_reason = (
            "owner_link_not_found" if ownership == "UNLINKED"
            else "owner_not_testable_without_virtual_mapping"
        )
        row.update(
            record_status="COMPLETE", confidence="MEDIUM",
            structure_status="COMPLETE_QSTRING", ownership_status=ownership,
            incomplete_reason="", ownership_reason=ownership_reason,
        )
    elif fmt == "qt-qstring":
        row.update(
            record_status="PARTIAL", confidence="MEDIUM",
            structure_status="EMBEDDED_QSTRING", ownership_status="NOT_APPLICABLE",
            ownership_reason="",
        )
    else:
        row.update(
            record_status="MARKER_ONLY", confidence="LOW",
            structure_status="BARE_MARKER", ownership_status="NOT_APPLICABLE",
            ownership_reason="",
        )
    return row


def _base_row(path: Path, marker: dict) -> dict:
    return {
        "source_file": str(path.resolve()), "dump_type": infer_dump_type(path),
        "message_id": "", "chat_id": "", "message_timestamp": "",
        "message": marker["message"], "marker_valid": "true",
        "state": marker["state"], "marker_date": marker["marker_date"],
        "marker_time": marker["marker_time"], "sequence": marker["sequence"],
        "embedded_datetime": marker["embedded_datetime"],
        "text_offset_dec": marker["offset"],
        "text_offset_hex": f"0x{marker['offset']:X}",
        "encoding": marker["encoding"],
    }


def iter_records(data, source_file: str,
                 max_text_chars: int = 4096) -> Iterator[dict]:
    path = Path(source_file)
    dump = None
    if bytes(data[:4]) == b"MDMP":
        try:
            dump = MiniDump(data)
        except (ValueError, struct.error):
            pass
    boundary = dump.boundary if dump is not None else lambda _offset: len(data)
    markers = list(iter_markers(data))
    qstrings: dict[int, dict] = {}
    qstring_by_marker: dict[int, dict] = {}
    for marker in markers:
        parsed = parse_qstring(data, marker, boundary(marker["offset"]), max_text_chars)
        if parsed is not None:
            qstrings[parsed["structure_offset"]] = parsed
            qstring_by_marker[marker["offset"]] = parsed
    owner_links = find_owner_links(data, dump, qstrings) if dump is not None else {}

    for marker in markers:
        row = _base_row(path, marker)
        parsed = qstring_by_marker.get(marker["offset"])
        if parsed is None:
            row.update({
                "record_format": "bare-marker", "record_status": "MARKER_ONLY",
                "confidence": "LOW", "incomplete_reason": "no_qstring_header",
                "structure_offset_dec": marker["offset"],
                "structure_offset_hex": f"0x{marker['offset']:X}",
                "record_end_dec": marker["end"],
                "record_end_hex": f"0x{marker['end']:X}",
                "owner_offset_dec": "", "owner_offset_hex": "",
                "owner_virtual_address": "", "qstring_virtual_address": "",
                "container_text": marker["message"], "qstring_refcount": "",
                "qstring_size": "", "qstring_capacity": "",
                "qstring_capacity_reserved": "", "terminator_valid": "",
                "evidence_hex": bytes(data[max(0, marker["offset"] - 32):
                    min(len(data), marker["end"] + 32)]).hex(),
            })
            yield normalize_semantics(row)
            continue

        owner = owner_links.get(parsed["structure_offset"])
        if owner is not None and parsed["exact_qstring"]:
            status, confidence, reason = "COMPLETE", "HIGH", ""
            record_format = "telegram-owner-qstring"
        elif parsed["exact_qstring"]:
            status, confidence = "PARTIAL", "MEDIUM"
            reason, record_format = "unlinked_qstring_copy", "qt-qstring"
        else:
            status, confidence = "PARTIAL", "MEDIUM"
            reason = "marker_embedded_in_larger_qstring"
            record_format = "qt-qstring"
        structure, record_end = parsed["structure_offset"], parsed["record_end"]
        qva = dump.virtual_address(structure) if dump is not None else None
        row.update({
            "record_format": record_format, "record_status": status,
            "confidence": confidence, "incomplete_reason": reason,
            "structure_offset_dec": structure,
            "structure_offset_hex": f"0x{structure:X}",
            "record_end_dec": record_end, "record_end_hex": f"0x{record_end:X}",
            "owner_offset_dec": owner[0] if owner else "",
            "owner_offset_hex": f"0x{owner[0]:X}" if owner else "",
            "owner_virtual_address": f"0x{owner[1]:X}" if owner else "",
            "qstring_virtual_address": f"0x{qva:X}" if qva is not None else "",
            "container_text": parsed["container_text"],
            "qstring_refcount": parsed["qstring_refcount"],
            "qstring_size": parsed["qstring_size"],
            "qstring_capacity": parsed["qstring_capacity"],
            "qstring_capacity_reserved": str(
                parsed["qstring_capacity_reserved"]
            ).lower(),
            "terminator_valid": "true",
            "evidence_hex": bytes(data[structure:
                min(boundary(structure), record_end + 32)]).hex(),
        })
        yield normalize_semantics(row)


def summarize(rows: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for raw_row in rows:
        row = normalize_semantics(raw_row)
        groups[row["message"]].append(row)
    output = []
    for marker, items in sorted(groups.items()):
        best = max(items, key=lambda row: (
            STATUS_RANK[row["record_status"]], CONFIDENCE_RANK[row["confidence"]]
        ))
        counts = defaultdict(int)
        for item in items:
            counts[item["record_status"]] += 1
        sources = sorted({item["source_file"] for item in items})
        output.append({
            "message": marker, "best_status": best["record_status"],
            "best_confidence": best["confidence"],
            "best_structure_status": best["structure_status"],
            "best_ownership_status": best["ownership_status"],
            "state": best["state"],
            "marker_date": best["marker_date"], "marker_time": best["marker_time"],
            "sequence": best["sequence"],
            "embedded_datetime": best["embedded_datetime"],
            "occurrence_count": len(items),
            "complete_occurrences": counts["COMPLETE"],
            "partial_occurrences": counts["PARTIAL"],
            "marker_only_occurrences": counts["MARKER_ONLY"],
            "source_count": len(sources), "source_files": " | ".join(sources),
            "record_formats": " | ".join(sorted({x["record_format"] for x in items})),
            "encodings": " | ".join(sorted({x["encoding"] for x in items})),
            "mapping_statuses": " | ".join(sorted({x["mapping_status"] for x in items})),
            "ownership_statuses": " | ".join(sorted({x["ownership_status"] for x in items})),
            "incomplete_reasons": " | ".join(sorted(
                {x["incomplete_reason"] for x in items if x["incomplete_reason"]}
            )),
            "ownership_reasons": " | ".join(sorted(
                {x["ownership_reason"] for x in items if x["ownership_reason"]}
            )),
            "evidence_offsets": " | ".join(
                f"{Path(x['source_file']).name}@{x['text_offset_hex']}:{x['record_status']}"
                for x in items
            ),
        })
    return output


def write_csv_atomic(rows: Iterable[dict], fields: list[str], output: Path) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".telegram-structure-", suffix=".csv", dir=output.parent
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


def merge_result_csvs(paths: Iterable[str | os.PathLike[str]], output: Path) -> dict:
    rows = []
    for value in sorted({Path(x).resolve() for x in paths}):
        if value == output.resolve():
            raise ValueError("output must not overwrite an input result")
        with value.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            required = {"message", "record_status", "text_offset_hex"}
            if not required.issubset(reader.fieldnames or []):
                raise ValueError(f"not a Telegram structure CSV: {value}")
            rows.extend(reader)
    summaries = summarize(rows)
    write_csv_atomic(summaries, SUMMARY_FIELDS, output)
    return {
        "unique_messages": len(summaries), "input_rows": len(rows),
        "occurrences": len(rows),
        "complete_messages": sum(x["best_status"] == "COMPLETE" for x in summaries),
        "partial_messages": sum(x["best_status"] == "PARTIAL" for x in summaries),
        "marker_only_messages": sum(
            x["best_status"] == "MARKER_ONLY" for x in summaries
        ),
        "output_file": str(output.resolve()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", required=True, type=Path)
    parser.add_argument("--unique-output", type=Path)
    parser.add_argument("--max-text-chars", type=int, default=4096)
    args = parser.parse_args()
    if not 64 <= args.max_text_chars <= 1_000_000:
        parser.error("max-text-chars must be between 64 and 1000000")
    try:
        with args.input.open("rb") as source:
            if args.input.stat().st_size:
                with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
                    rows = list(iter_records(data, str(args.input), args.max_text_chars))
            else:
                rows = []
        write_csv_atomic(rows, FIELDS, args.output.resolve())
        if args.unique_output:
            write_csv_atomic(summarize(rows), SUMMARY_FIELDS, args.unique_output.resolve())
        print({
            "occurrences": len(rows),
            "complete": sum(x["record_status"] == "COMPLETE" for x in rows),
            "partial": sum(x["record_status"] == "PARTIAL" for x in rows),
            "marker_only": sum(x["record_status"] == "MARKER_ONLY" for x in rows),
        })
        return 0
    except (OSError, ValueError, struct.error) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
