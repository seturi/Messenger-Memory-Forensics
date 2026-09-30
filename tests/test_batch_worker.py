"""Synthetic packaging checks for the public batch worker."""

import csv
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import batch_analysis_gui as batch
from parsers.viber_parser import PATTERN1, PATTERN2
from parsers.whatsapp_structure_parser import SQL_ANCHOR


def signal_fixture(message):
    """Build a small in-memory SQLite record with no captured user data."""
    columns = ["rowid", "id", "json", "readStatus", "expires_at", "sent_at", "schemaVersion",
               "conversationId", "received_at", "hasAttachments", "hasFileAttachments",
               "hasVisualMediaAttachments", "expireTimer", "expirationStartTimestamp",
               "type", "body"] + [f"extra{i}" for i in range(16, 35)]
    values = [None] * 35
    values[1] = "12345678-1234-abcd-9876-123456789abc"
    values[2] = '{"bodyRanges": []}'
    values[3], values[5], values[6] = 0, 1788225420000, 15
    values[7], values[8] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 1788224920000
    values[9:12] = [0, 0, 0]
    values[13], values[14], values[15] = 1788225422000, "incoming", message
    values[29], values[30] = 1788225421000, 1788225420000
    definitions = ["rowid INTEGER PRIMARY KEY"] + [
        name + (" TEXT" if i in (1, 2, 7, 14, 15) else " INTEGER")
        for i, name in enumerate(columns) if i > 0
    ]
    connection = sqlite3.connect(":memory:")
    connection.execute("PRAGMA page_size=4096")
    connection.execute("CREATE TABLE messages (" + ",".join(definitions) + ")")
    connection.execute("INSERT INTO messages VALUES (" + ",".join("?" for _ in values) + ")", values)
    data = connection.serialize()
    connection.close()
    return data


def whatsapp_fixture(message):
    def field(value):
        raw = value.encode("utf-8")
        return b"S" + bytes([len(raw)]) + raw

    return (SQL_ANCHOR + field("1000000175") + field("159026046357636@lid")
            + field("1788352629") + field(message))


class BatchWorkerTests(unittest.TestCase):
    def test_extensions(self):
        self.assertEqual(batch.extensions_from_text("raw,*.dmp"), [".dmp", ".raw"])
        with self.assertRaises(ValueError):
            batch.extensions_from_text("../raw")

    def test_empty_inputs_produce_csv_and_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input"
            source.mkdir()
            (source / "empty.raw").write_bytes(b"")
            for parser in batch.PARSERS:
                with self.subTest(parser=parser):
                    config_path = batch.create_run(source, root / "output", parser, [".raw"])
                    self.assertEqual(batch.worker_main(config_path), 0)
                    config = json.loads(config_path.read_text(encoding="utf-8"))
                    self.assertEqual(config["state"], "completed")
                    self.assertEqual(config["total"], 1)
                    with (config_path.parent / "summary.csv").open(encoding="utf-8-sig", newline="") as stream:
                        rows = list(csv.DictReader(stream))
                    self.assertEqual(len(rows), 1)
                    self.assertEqual(rows[0]["status"], "completed")
                    self.assertEqual(rows[0]["records"], "0")
                    self.assertTrue(Path(rows[0]["output_file"]).is_file())

    def test_synthetic_messages_round_trip(self):
        fixtures = {
            "Signal": signal_fixture("signal test message"),
            "WhatsApp": whatsapp_fixture("whatsapp test message"),
            "Viber": PATTERN1 + b"viber test message" + PATTERN2,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input"
            source.mkdir()
            for parser, data in fixtures.items():
                with self.subTest(parser=parser):
                    (source / "sample.raw").write_bytes(data)
                    config_path = batch.create_run(source, root / "output", parser, [".raw"])
                    self.assertEqual(batch.worker_main(config_path), 0)
                    with (config_path.parent / "summary.csv").open(encoding="utf-8-sig", newline="") as stream:
                        result = next(csv.DictReader(stream))
                    self.assertGreater(int(result["records"]), 0)
                    with Path(result["output_file"]).open(encoding="utf-8-sig", newline="") as stream:
                        row = next(csv.DictReader(stream))
                    field = "text" if parser == "Viber" else "message"
                    self.assertEqual(row[field], parser.lower() + " test message")


if __name__ == "__main__":
    unittest.main()
