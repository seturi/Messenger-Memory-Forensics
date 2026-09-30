"""Read-only mapped input and streaming, atomic CSV output."""

import csv
import mmap
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def mapped_input(path):
    with open(path, "rb") as source:
        if os.fstat(source.fileno()).st_size == 0:
            yield b""
        else:
            with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
                yield data


def check_output(input_path, output_path):
    source, destination = Path(input_path).resolve(), Path(output_path).resolve()
    if source == destination or (destination.exists() and os.path.samefile(source, destination)):
        raise ValueError("Output must not overwrite the input evidence file")


def write_csv(records, fields, output_path):
    """Keep any existing output intact if scanning/writing fails."""
    destination = Path(output_path).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".parser-", suffix=".csv", dir=destination.parent)
    count = 0
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8-sig") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for record in records:
                writer.writerow(record)
                count += 1
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return count
