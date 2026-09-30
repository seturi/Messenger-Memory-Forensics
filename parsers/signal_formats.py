"""Bounded decoders for Signal SQLite records and V8 property streams.

No message-content markers or executable deserialization are used.
"""
import json
import math
import re
import struct

UUID_TEXT = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
UUID_BYTES = re.compile(rb"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
V8_ID = b'\x22\x02id\x22\x24'
MIN_TIME = 946684800000
MAX_TIME = 4102444800000


def valid_time(value):
    return (type(value) in (int, float) and math.isfinite(value)
            and MIN_TIME <= value < MAX_TIME and int(value) == value)


def valid_message(obj):
    return (isinstance(obj.get("id"), str) and UUID_TEXT.fullmatch(obj["id"])
            and isinstance(obj.get("body"), str)
            and isinstance(obj.get("conversationId"), str)
            and UUID_TEXT.fullmatch(obj["conversationId"])
            and obj.get("type") in ("incoming", "outgoing")
            and valid_time(obj.get("sent_at")))


def sqlite_varint(data, pos, end):
    value = 0
    for index in range(9):
        if pos >= end:
            raise ValueError("Truncated SQLite varint")
        byte = data[pos]
        pos += 1
        if index == 8:
            return (value << 8) | byte, pos
        value = (value << 7) | (byte & 127)
        if byte < 128:
            return value, pos
    raise ValueError("Invalid SQLite varint")


def serial_length(serial):
    if serial in (10, 11):
        raise ValueError("Reserved SQLite serial type")
    if serial < 12:
        return (0, 1, 2, 3, 4, 6, 8, 8, 0, 0)[serial]
    return (serial - 12) // 2


def sqlite_record(data, start, limit, max_bytes):
    header_size, pos = sqlite_varint(data, start, limit)
    header_end = start + header_size
    if not 17 <= header_size <= 256 or header_end > limit:
        raise ValueError("Invalid SQLite record header")
    serials = []
    while pos < header_end:
        serial, pos = sqlite_varint(data, pos, header_end)
        serials.append(serial)
    # Signal messages table layout observed in the supplied 8.25.0 dump.
    if len(serials) not in (34, 35) or serials[:2] != [0, 85]:
        raise ValueError("Not a messages table record")
    if serials[2] < 13 or serials[2] % 2 != 1:
        raise ValueError("JSON column must be text")
    sizes = [serial_length(t) for t in serials]
    record_end = header_end + sum(sizes)
    if record_end > limit or record_end - start > max_bytes:
        raise ValueError("Truncated/oversize SQLite record")
    values, spans = [], []
    pos = header_end
    for serial, size in zip(serials, sizes):
        end = pos + size
        raw = data[pos:end]
        if serial == 0:
            value = None
        elif serial in (8, 9):
            value = serial - 8
        elif serial == 7:
            value = struct.unpack(">d", raw)[0]
        elif serial < 7:
            value = int.from_bytes(raw, "big", signed=True)
        elif serial % 2:
            value = raw.decode("utf-8")
        else:
            value = raw
        values.append(value)
        spans.append((pos, end))
        pos = end
    obj = {
        "id": values[1], "sent_at": values[5], "conversationId": values[7],
        "received_at": values[8], "expirationStartTimestamp": values[13],
        "type": values[14], "body": values[15],
    }
    if not valid_message(obj):
        raise ValueError("SQLite identity/content fields do not validate")
    if type(values[6]) is not int or not 0 <= values[6] <= 100:
        raise ValueError("Invalid message schemaVersion")
    metadata = json.loads(values[2])
    if not isinstance(metadata, dict):
        raise ValueError("Message metadata must be a JSON object")
    # Reject another table with merely coincidental string/integer columns.
    if not any(key in metadata for key in ("bodyRanges", "sendStateByConversationId",
                                         "attachments", "errors", "preview")):
        raise ValueError("Missing Signal message metadata")
    obj["sendStateByConversationId"] = metadata.get("sendStateByConversationId")
    # These indices are validated against matching V8 fields in the provided capture.
    # The observed 35-column schema and its 34-column predecessor use these positions.
    if len(values) in (34, 35):
        if not valid_time(values[29]) or not valid_time(values[30]):
            raise ValueError("Invalid trailing message timestamps; possibly fragmented/overflow payload")
        obj["received_at_ms"] = values[29]
        obj["timestamp"] = values[30]
    return {
        "values": obj, "start": start, "end": record_end,
        "body_start": spans[15][0], "body_end": spans[15][1],
        "encoding": "utf-8", "format": "sqlite-record",
        "validation": "typed-record", "serials": serials,
    }


def iter_sqlite_records(data, max_bytes, boundary):
    pos, last_start = 0, -1
    while True:
        anchor = data.find(b"\x00\x55", pos)
        if anchor < 0:
            return
        pos = anchor + 2
        for start in (anchor - 1, anchor - 2):
            if start < 0 or start == last_start:
                continue
            try:
                header, after = sqlite_varint(data, start, min(anchor + 1, len(data)))
                if after != anchor or not 17 <= header <= 256:
                    continue
                # Cheap UUID check before decoding every column/JSON object.
                uuid_start = start + header
                raw_id = data[uuid_start:uuid_start + 36]
                if UUID_BYTES.fullmatch(raw_id) is None:
                    continue
                result = sqlite_record(data, start, boundary(start), max_bytes)
                last_start = start
                yield result
                break
            except (ValueError, UnicodeError, struct.error, IndexError, RecursionError):
                continue


class V8Reader:
    """Non-executing subset of V8 ValueSerializer with strict resource limits."""
    def __init__(self, data, start, end, max_nodes=10000):
        self.data, self.pos, self.end = data, start, end
        self.max_nodes = max_nodes
        self.nodes = 0
        self.string_span = None

    def take(self, size):
        if size < 0 or self.pos + size > self.end:
            raise ValueError("Truncated V8 value")
        start = self.pos
        self.pos += size
        return self.data[start:self.pos]

    def uint(self):
        value = 0
        for shift in range(0, 35, 7):
            byte = self.take(1)[0]
            value |= (byte & 127) << shift
            if byte < 128:
                if value > 0xffffffff:
                    raise ValueError("V8 uint32 overflow")
                return value
        raise ValueError("Invalid V8 varint")

    def tag(self):
        tag = self.take(1)[0]
        while tag == 0:
            tag = self.take(1)[0]
        return tag

    def peek(self):
        while self.pos < self.end and self.data[self.pos] == 0:
            self.pos += 1
        if self.pos >= self.end:
            raise ValueError("Truncated V8 value")
        return self.data[self.pos]

    def value(self, depth=0):
        self.nodes += 1
        if depth > 24 or self.nodes > self.max_nodes:
            raise ValueError("V8 nesting/item limit exceeded")
        tag = self.tag()
        self.string_span = None
        if tag in (ord("_"), ord("0"), ord("-")):
            return None
        if tag in (ord("T"), ord("F")):
            return tag == ord("T")
        if tag in (ord("I"), ord("U")):
            number = self.uint()
            return (number >> 1) ^ -(number & 1) if tag == ord("I") else number
        if tag == ord("N"):
            return struct.unpack("<d", self.take(8))[0]
        if tag in (ord('"'), ord("S"), ord("c")):
            size = self.uint()
            start = self.pos
            encoding = {ord('"'): "latin-1", ord("S"): "utf-8", ord("c"): "utf-16le"}[tag]
            if encoding == "utf-16le" and size % 2:
                raise ValueError("Odd UTF-16 byte length")
            text = self.take(size).decode(encoding)
            self.string_span = (start, self.pos, encoding)
            return text
        if tag == ord("o"):
            values, _ = self.properties(depth + 1, complete=True)
            return values
        if tag == ord("A"):
            size = self.uint()
            if size > self.max_nodes - self.nodes:
                raise ValueError("V8 array length limit")
            values = [self.value(depth + 1) for _ in range(size)]
            # Arrays with named properties are not needed by the observed message format.
            if self.tag() != ord("$") or self.uint() != 0 or self.uint() != size:
                raise ValueError("Invalid/unsupported V8 array trailer")
            return values
        # Object references need the containing serialization's object table.
        # They and host objects are explicitly rejected rather than guessed.
        raise ValueError(f"Unsupported V8 tag: 0x{tag:02x}")

    def properties(self, depth=0, complete=False):
        values, spans = {}, {}
        count = 0
        while self.peek() != ord("{"):
            key_pos = self.pos
            key = self.value(depth + 1)
            if not isinstance(key, str) or not key or len(key) > 256 or key in values:
                raise ValueError("Invalid/duplicate V8 property")
            value = self.value(depth + 1)
            values[key] = value
            spans[key] = (key_pos, self.string_span)
            count += 1
            if count > 256:
                raise ValueError("V8 property limit")
        self.tag()
        total = self.uint()
        if total < count or total > 256 or (complete and total != count):
            raise ValueError("V8 property count mismatch")
        return values, spans


def iter_v8_records(data, max_bytes, boundary, include_fragments=False):
    pos = 0
    while True:
        anchor = data.find(V8_ID, pos)
        if anchor < 0:
            return
        pos = anchor + len(V8_ID)
        limit = min(boundary(anchor), anchor + max_bytes)
        try:
            reader = V8Reader(data, anchor, limit)
            obj, spans = reader.properties()
            if not valid_message(obj) or not spans.get("body", (None, None))[1]:
                continue
            end = reader.pos
            start, validation = anchor, "validated-property-tail"
            # An id/body suffix is insufficient: recover the containing object,
            # consume every direct property, and verify the exact trailer count.
            lower = max(0, anchor - max_bytes)
            candidate = anchor
            while True:
                candidate = data.rfind(b'o', lower, candidate)
                if candidate < 0:
                    break
                if end - candidate > max_bytes or boundary(candidate) < end:
                    continue
                try:
                    full = V8Reader(data, candidate + 1, end)
                    extended, extended_spans = full.properties(complete=True)
                    if (full.pos == end and extended_spans.get("id", (None,))[0] == anchor
                            and valid_message(extended)):
                        obj, spans = extended, extended_spans
                        start, validation = candidate, "complete-object"
                        break
                except (ValueError, UnicodeError, struct.error, KeyError, RecursionError):
                    pass
            if validation != "complete-object" and not include_fragments:
                continue
            body_start, body_end, encoding = spans["body"][1]
            yield {"values": obj, "start": start, "end": end, "body_start": body_start,
                   "body_end": body_end, "encoding": encoding, "format": "v8-property-stream",
                   "validation": validation, "serials": []}
        except (ValueError, UnicodeError, struct.error, KeyError, RecursionError):
            continue
