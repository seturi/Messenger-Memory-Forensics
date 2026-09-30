"""Signal structured message recovery. Offsets refer to input-file bytes."""
import argparse
import heapq
import struct
import json
import logging
import re
from datetime import datetime, timezone

try:
    from .parser_io import mapped_input, check_output, write_csv
    from .signal_formats import iter_sqlite_records, iter_v8_records, valid_time
    from .minidump_info import MiniDump
except ImportError:
    from parser_io import mapped_input, check_output, write_csv
    from signal_formats import iter_sqlite_records, iter_v8_records, valid_time
    from minidump_info import MiniDump

LOG = logging.getLogger(__name__)
UUID_RE = re.compile(rb"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
FIELDS = ['id', 'offset', 'size', 'message_id', 'status', 'sent_at',
          'conversation_id', 'received_at', 'expirationStartTimestamp', 'message',
          'timestamp', 'message_offset', 'message_hex', 'decode_errors',
          'record_format', 'validation', 'record_status', 'confidence',
          'structure_status', 'ownership_status', 'mapping_status',
          'incomplete_reason', 'ownership_reason',
          'message_type', 'message_encoding',
          'sent_at_ms', 'received_at_raw', 'received_at_ms', 'timestamp_ms',
          'send_state_json', 'sqlite_serial_types', 'record_hex',
          'process_id', 'process_role', 'signal_version', 'virtual_address',
          'occurrence_count', 'evidence_json', 'conflicting_fields']

class MessageParser:
    START_SIG = bytes.fromhex(
        "240055853D08000501550508080800051D53000000080800000000080800080505080000")
    OUTGOING_SIG = b'outgoing'
    MAX_RANGE = 0x200

    def __init__(self, data, max_search=1000, mode="auto", max_record_bytes=1048576):
        if max_search < 12:
            raise ValueError("max_search must be at least 12")
        if mode not in ("auto", "sqlite", "v8", "legacy"):
            raise ValueError("Unknown Signal decoder mode")
        if max_record_bytes < 128:
            raise ValueError("max_record_bytes must be at least 128")
        self.data = data
        self.max_search = max_search
        self.mode = mode
        self.max_record_bytes = max_record_bytes
        self.messages = []
        self.dump = MiniDump(data) if data[:4] == b"MDMP" else None
        self.process_info = self.dump.inventory() if self.dump else {}


    def parse_timestamp(self, data, offset):
        if offset < 0 or offset + 6 > len(data):
            return None
        return int.from_bytes(data[offset:offset + 6], "big")

    def timestamp_to_iso(self, ts):
        return datetime.fromtimestamp(ts / 1000, timezone.utc).isoformat().replace("+00:00", "Z")

    def find_sent_at_timestamp(self, data, start, end):
        end = min(end, len(data))
        i = data.find(b'\x01', start, end)
        while i != -1 and i + 6 <= end:
            ts = self.parse_timestamp(data, i)
            if 1577836800000 <= ts <= 2051222400000:
                return ts
            i = data.find(b'\x01', i + 1, end)
        return None

    def find_timestamp_pair(self, data, start, sent_at, max_search=1000):
        # Byte search includes a complete pair ending exactly at EOF.
        pair = sent_at.to_bytes(6, "big") * 2
        i = data.find(pair, start, min(len(data), start + max_search))
        return None if i == -1 else i

    def extract_uuid(self, data, start, max_len=100):
        match = UUID_RE.search(data, start, min(len(data), start + max_len + 35))
        return match.group().decode("ascii") if match else None

    def extract_json_data(self, data, start, end):
        result = {'status': None, 'conversation_id': None, 'message': None}
        # raw_decode handles escaped quotes and braces inside JSON strings.
        text = data[start:end].decode("utf-8", errors="replace")
        decoder = json.JSONDecoder()
        pos = text.find("{")
        while pos != -1:
            try:
                obj, consumed = decoder.raw_decode(text, pos)
            except (ValueError, RecursionError):
                pos = text.find("{", pos + 1)
                continue
            if isinstance(obj, dict):
                states = obj.get("sendStateByConversationId")
                if isinstance(states, dict):
                    for conv_id, state in states.items():
                        if isinstance(state, dict) and 'status' in state:
                            result.update(status=state['status'], conversation_id=conv_id)
                            return result
            pos = text.find("{", consumed)
        return result

    def extract_conversation_id(self, data, start, end):
        pos = data.find(b'\x0f', start, end)
        while pos != -1:
            match = UUID_RE.match(data, pos + 1, min(end, len(data)))
            if match:
                return match.group().decode("ascii")
            pos = data.find(b'\x0f', pos + 1, end)
        return None

    def extract_message_text(self, data, outgoing_idx, end_idx):
        raw = data[outgoing_idx + len(self.OUTGOING_SIG):end_idx]
        # Decode before removing structural controls, preserving Unicode/newlines.
        text = raw.decode("utf-8", errors="replace")
        text = "".join(c for c in text if ord(c) >= 32 or c in "\t\r\n")
        return text.strip() or None

    def _iter_legacy(self):
        """Original fixed-header heuristic, retained for explicit compatibility."""
        data, offset = self.data, 0
        while True:
            start = data.find(self.START_SIG, offset)
            if start == -1:
                return
            offset = start + len(self.START_SIG)
            search_end = min(len(data), offset + self.MAX_RANGE)
            # A damaged candidate must not borrow fields from the next block.
            limit = min(len(data), search_end + self.max_search + len(self.OUTGOING_SIG))
            next_start = data.find(self.START_SIG, offset, limit)
            if next_start != -1:
                limit = next_start
            outgoing = data.find(self.OUTGOING_SIG, offset, min(search_end, limit))
            if outgoing == -1:
                continue
            sent_at = self.find_sent_at_timestamp(data, offset, outgoing)
            if sent_at is None:
                continue
            text_start = outgoing + len(self.OUTGOING_SIG)
            end = self.find_timestamp_pair(data, text_start, sent_at,
                                           min(self.max_search, limit - text_start))
            if end is None:
                continue
            block_end = end + 12
            msg_id = self.extract_uuid(data, start, min(100, block_end - start - 35))
            metadata = self.extract_json_data(data, start, end)
            raw = data[text_start:end]
            try:
                raw.decode("utf-8")
                decode_errors = False
            except UnicodeDecodeError:
                decode_errors = True
            stamp = self.timestamp_to_iso(sent_at)
            LOG.debug("Signal candidate at 0x%X, %d bytes", start, block_end - start)
            yield {
                'id': msg_id, 'offset': f"0x{start:08x}", 'size': block_end - start,
                'message_id': msg_id, 'status': metadata['status'], 'sent_at': stamp,
                'conversation_id': self.extract_conversation_id(data, start, block_end)
                                   or metadata['conversation_id'],
                # Legacy field names retained; semantic meanings require sample validation.
                'received_at': stamp, 'expirationStartTimestamp': stamp,
                'message': self.extract_message_text(data, outgoing, end), 'timestamp': stamp,
                'message_offset': f"0x{text_start:08x}", 'message_hex': raw.hex(),
                'decode_errors': decode_errors,
            }
            offset = block_end

    def _process_fields(self, offset):
        va = self.dump.virtual_address(offset) if self.dump else None
        return {
            "process_id": self.process_info.get("pid"),
            "process_role": self.process_info.get("process_role", "unknown"),
            "signal_version": self.process_info.get("signal_version", ""),
            "virtual_address": hex(va) if va is not None else "",
        }

    def _modern_record(self, record):
        obj = record["values"]
        start, end = record["start"], record["end"]
        body_start, body_end = record["body_start"], record["body_end"]
        def iso(value):
            return self.timestamp_to_iso(value) if valid_time(value) else None
        state = obj.get("sendStateByConversationId")
        statuses = sorted({str(value["status"]) for value in state.values()
                           if isinstance(value, dict) and value.get("status") is not None}) if isinstance(state, dict) else []
        timestamp = obj.get("timestamp")
        received_ms = obj.get("received_at_ms")
        complete = record["validation"] in ("typed-record", "complete-object")
        result = {
            "id": obj["id"], "offset": f"0x{start:08x}", "size": end-start,
            "message_id": obj["id"], "status": "|".join(statuses) or None,
            "sent_at": iso(obj["sent_at"]), "conversation_id": obj["conversationId"],
            "received_at": iso(received_ms),
            "expirationStartTimestamp": iso(obj.get("expirationStartTimestamp")),
            "message": obj["body"], "timestamp": iso(timestamp),
            "message_offset": f"0x{body_start:08x}",
            "message_hex": self.data[body_start:body_end].hex(), "decode_errors": False,
            "record_format": record["format"], "validation": record["validation"],
            "record_status": "COMPLETE" if complete else "PARTIAL",
            "confidence": "HIGH" if complete else "MEDIUM",
            "structure_status": "COMPLETE_RECORD" if complete else "PARTIAL_RECORD",
            "ownership_status": "NOT_REQUIRED",
            "mapping_status": "MINIDUMP_VA" if self.dump else "FLAT_BYTES",
            "incomplete_reason": "" if complete else "missing_complete_object_envelope",
            "ownership_reason": "",
            "message_type": obj["type"], "message_encoding": record["encoding"],
            "sent_at_ms": int(obj["sent_at"]), "received_at_raw": obj.get("received_at"),
            "received_at_ms": received_ms, "timestamp_ms": timestamp,
            "send_state_json": json.dumps(state, ensure_ascii=False, sort_keys=True) if state else "",
            "sqlite_serial_types": json.dumps(record["serials"]) if record["serials"] else "",
            "record_hex": self.data[start:end].hex(),
        }
        result.update(self._process_fields(start))
        return result

    def iter_occurrences(self, include_fragments=False):
        """Stream evidence occurrences; fragments/heuristics require explicit opt-in."""
        boundary = self.dump.boundary if self.dump else lambda offset: len(self.data)
        streams = []
        if self.mode in ("auto", "sqlite"):
            streams.append(iter_sqlite_records(self.data, self.max_record_bytes, boundary))
        if self.mode in ("auto", "v8"):
            streams.append(iter_v8_records(self.data, self.max_record_bytes, boundary, include_fragments))
        modern = heapq.merge(*streams, key=lambda record: record["start"]) if streams else iter(())
        for record in modern:
            yield self._modern_record(record)
        if self.mode == "legacy" or (self.mode == "auto" and include_fragments):
            for record in self._iter_legacy():
                offset = int(record["offset"], 16)
                # Real SQLite records matching the old literal header are already
                # recovered by the typed decoder. Do not report the heuristic twice.
                if self.mode == "auto":
                    try:
                        from .signal_formats import sqlite_record
                    except ImportError:
                        from signal_formats import sqlite_record
                    try:
                        sqlite_record(self.data, offset, boundary(offset), self.max_record_bytes)
                        continue
                    except (ValueError, UnicodeError, struct.error, IndexError):
                        pass
                record.update(record_format="legacy-signature", validation="legacy-heuristic",
                              record_status="PARTIAL", confidence="LOW",
                              structure_status="HEURISTIC_FRAGMENT",
                              ownership_status="NOT_REQUIRED",
                              mapping_status="MINIDUMP_VA" if self.dump else "FLAT_BYTES",
                              incomplete_reason="untyped_legacy_heuristic",
                              ownership_reason="",
                              message_type="outgoing", message_encoding="utf-8",
                              record_hex=self.data[offset:offset+record["size"]].hex())
                record.update(self._process_fields(offset))
                yield record

    def iter_messages(self, include_fragments=False):
        """One row per message UUID; prefer SQLite and preserve all evidence offsets.

        This counts recovered identities, not currently visible/undeleted messages.
        Historical but structurally complete messages remain eligible.
        """
        if self.mode == "legacy":
            yield from self.iter_occurrences()
            return
        groups = {}
        core = ("message", "conversation_id", "sent_at_ms", "message_type")
        for row in self.iter_occurrences(include_fragments=include_fragments):
            key = row["message_id"].lower()
            evidence = {"offset": row["offset"], "size": row["size"],
                        "record_format": row["record_format"], "validation": row["validation"],
                        "record_status": row["record_status"],
                        "incomplete_reason": row["incomplete_reason"]}
            if key not in groups:
                groups[key] = [row, [], set()]
            group = groups[key]
            differences = [field for field in core if row[field] != group[0][field]]
            group[2].update(differences)
            if differences:
                evidence["variant"] = {field: row[field] for field in core}
                # Keep the first version too, even if the representative changes.
                if "variant" not in group[1][0]:
                    group[1][0]["variant"] = {field: group[0][field] for field in core}
            group[1].append(evidence)
            if ((row["record_status"] == "COMPLETE" and group[0]["record_status"] != "COMPLETE")
                    or (row["record_status"] == group[0]["record_status"]
                        and row["record_format"] == "sqlite-record"
                        and group[0]["record_format"] != "sqlite-record")):
                group[0] = row
        for row, evidence, conflicts in groups.values():
            row["occurrence_count"] = len(evidence)
            row["evidence_json"] = json.dumps(evidence, ensure_ascii=False)
            row["conflicting_fields"] = "|".join(sorted(conflicts))
            yield row

    def parse_messages(self):
        """Compatibility API; repeated calls do not append duplicates."""
        self.messages = list(self.iter_messages())
        return self.messages

    def save_to_csv(self, filename):
        return write_csv(self.messages, FIELDS, filename)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("memory_dump_file")
    ap.add_argument("output_csv", nargs="?")
    ap.add_argument("--max-search", type=int, default=1000,
                    help="Maximum bytes after outgoing to search for the timestamp pair")
    ap.add_argument("--mode", choices=("auto", "sqlite", "v8", "legacy"), default="auto")
    ap.add_argument("--max-record-bytes", type=int, default=1048576,
                    help="Bound SQLite/V8 candidate size; does not control legacy timestamp search")
    ap.add_argument("--evidence", action="store_true",
                    help="Export all occurrences, including incomplete V8 tails and legacy heuristics")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.WARNING)
    from pathlib import Path
    out = args.output_csv or str(Path(args.memory_dump_file).with_suffix("")) + "_parsed.csv"
    try:
        check_output(args.memory_dump_file, out)
        with mapped_input(args.memory_dump_file) as data:
            parser = MessageParser(data, args.max_search, args.mode, args.max_record_bytes)
            if parser.process_info:
                print("Process: PID={} role={} Signal={}".format(
                    parser.process_info.get("pid"), parser.process_info.get("process_role"),
                    parser.process_info.get("signal_version")))
            rows = parser.iter_occurrences(include_fragments=True) if args.evidence else parser.iter_messages()
            count = write_csv(rows, FIELDS, out)
    except (OSError, ValueError, struct.error) as exc:
        ap.exit(1, f"Error: {exc}\n")
    print(f"Signal: {count} records -> {out}")

if __name__ == "__main__":
    main()
