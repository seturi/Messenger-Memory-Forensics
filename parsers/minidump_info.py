"""Read-only x64 minidump memory mapping and PEB process-role attribution."""
import argparse
import bisect
import csv
import json
import mmap
import re
import struct
from datetime import datetime, timezone
from pathlib import Path

class MiniDump:
    def __init__(self, data):
        self.data = data
        if data[:4] != b"MDMP":
            raise ValueError("Not a Microsoft minidump")
        if len(data) < 32:
            raise ValueError("Truncated minidump header")
        count, directory = struct.unpack_from("<II", data, 8)
        if count > 4096 or directory + count * 12 > len(data):
            raise ValueError("Invalid minidump directory")
        self.streams = {}
        for i in range(count):
            kind, size, rva = struct.unpack_from("<III", data, directory+i*12)
            if rva + size > len(data):
                raise ValueError("Truncated minidump stream")
            self.streams[kind] = (rva, size)
        for kind, minimum in ((3, 4), (4, 4), (5, 4), (7, 2), (9, 16), (15, 12)):
            if kind in self.streams and self.streams[kind][1] < minimum:
                raise ValueError("Truncated minidump stream structure")
        self.ranges = []
        if 9 in self.streams:
            rva, _ = self.streams[9]
            count, file_offset = struct.unpack_from("<QQ", data, rva)
            if count > 1000000 or 16 + count * 16 > self.streams[9][1]:
                raise ValueError("Invalid Memory64List")
            for i in range(count):
                address, size = struct.unpack_from("<QQ", data, rva+16+i*16)
                if file_offset + size > len(data):
                    raise ValueError("Truncated minidump memory")
                if size:
                    self.ranges.append((address, address+size, file_offset))
                file_offset += size
        elif 5 in self.streams:
            rva, _ = self.streams[5]
            count, = struct.unpack_from("<I", data, rva)
            if count > 1000000 or 4 + count * 16 > self.streams[5][1]:
                raise ValueError("Invalid MemoryList")
            for i in range(count):
                address, size, file_offset = struct.unpack_from("<QII", data, rva+4+i*16)
                if file_offset + size > len(data):
                    raise ValueError("Truncated minidump memory")
                if size:
                    self.ranges.append((address, address+size, file_offset))
        self.ranges.sort()
        self.starts = [x[0] for x in self.ranges]
        self.file_ranges = sorted((off, off + end - start, start)
                                  for start, end, off in self.ranges)
        self.file_starts = [item[0] for item in self.file_ranges]

    def file_region(self, offset):
        index = bisect.bisect_right(self.file_starts, offset) - 1
        if index < 0:
            return None
        start, end, va = self.file_ranges[index]
        return (start, end, va) if offset < end else None

    def boundary(self, offset):
        region = self.file_region(offset)
        return region[1] if region else offset

    def virtual_address(self, offset):
        region = self.file_region(offset)
        return region[2] + offset - region[0] if region else None


    def read(self, address, size):
        chunks = []
        while size:
            idx = bisect.bisect_right(self.starts, address)-1
            if idx < 0:
                raise ValueError(f"Unmapped VA: {address:x}")
            start, end, off = self.ranges[idx]
            length = min(size, end-address)
            if length <= 0:
                raise ValueError(f"Unmapped VA: {address:x}")
            chunks.append(self.data[off+address-start:off+address-start+length])
            size -= length
            address += length
        return b"".join(chunks)

    def qword(self, address):
        return struct.unpack("<Q", self.read(address, 8))[0]

    def unicode_string(self, address):
        length, maximum, _, buffer = struct.unpack("<HHIQ", self.read(address,16))
        if length > maximum or length > 65534:
            raise ValueError("Invalid UNICODE_STRING")
        return self.read(buffer,length).decode("utf-16le", errors="replace")

    def inventory(self):
        d = self.data
        result = {"streams":sorted(self.streams), "memory_ranges":len(self.ranges)}
        if 15 in self.streams:
            off, _ = self.streams[15]
            size, flags, pid = struct.unpack_from("<III", d, off)
            if flags & 1:
                result["pid"] = pid
        if 7 in self.streams:
            result["processor_architecture"] = struct.unpack_from("<H",d,self.streams[7][0])[0]
        modules = []
        if 4 in self.streams:
            off, _ = self.streams[4]
            count, = struct.unpack_from("<I",d,off)
            if 4 + count * 108 > self.streams[4][1]:
                raise ValueError("Invalid ModuleList")
            for i in range(count):
                row = off+4+108*i
                base, size = struct.unpack_from("<QI",d,row)
                name_rva, = struct.unpack_from("<I",d,row+20)
                length, = struct.unpack_from("<I",d,name_rva)
                if length > 65534 or length % 2 or name_rva + 4 + length > len(d):
                    raise ValueError("Invalid minidump module name")
                name = d[name_rva+4:name_rva+4+length].decode("utf-16le",errors="replace")
                ms, ls = struct.unpack_from("<II",d,row+32)
                modules.append({"name":name,"base":hex(base),"size":size,
                                "version":f"{ms>>16}.{ms&65535}.{ls>>16}.{ls&65535}"})
            result["module_count"] = len(modules)
            result["signal_modules"] = [m for m in modules if any(k in m["name"].lower() for k in ("signal","node","sqlite"))]
        if 3 in self.streams:
            off, _ = self.streams[3]
            count, = struct.unpack_from("<I",d,off)
            if 4 + count * 48 > self.streams[3][1]:
                raise ValueError("Invalid ThreadList")
            result["thread_count"] = count
            if result.get("processor_architecture") == 9:
                for i in range(count):
                    teb, = struct.unpack_from("<Q",d,off+4+48*i+16)
                    try:
                        peb = self.qword(teb+0x60)
                        parameters = self.qword(peb+0x20)
                        result.update(teb=hex(teb),peb=hex(peb),
                                      image_path=self.unicode_string(parameters+0x60),
                                      command_line=self.unicode_string(parameters+0x70))
                        break
                    except (ValueError, struct.error):
                        continue
        command = result.get("command_line", "")
        kind = re.search(r"(?:^|\s)--type=([^\s]+)", command)
        if kind:
            role = kind.group(1)
            if role == "utility" and "--utility-sub-type=network.mojom.NetworkService" in command:
                role = "network-service"
        elif command and result.get("image_path", "").replace("\\", "/").rsplit("/", 1)[-1].lower() == "signal.exe":
            role = "main"
        else:
            role = "unknown"
        result["process_role"] = role
        signal = next((m for m in result.get("signal_modules", [])
                       if m["name"].replace("\\", "/").rsplit("/", 1)[-1].lower() == "signal.exe"), None)
        result["signal_version"] = signal["version"] if signal else ""
        result["dump_timestamp_utc"] = datetime.fromtimestamp(
            struct.unpack_from("<I",d,20)[0], timezone.utc).isoformat()
        return result

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", help="Minidump file or folder (recursive)")
    ap.add_argument("--csv", required=True)
    args = ap.parse_args()
    source = Path(args.input)
    files = sorted(source.rglob("*.dmp")) if source.is_dir() else [source]
    fields = ["file", "pid", "process_role", "signal_version", "command_line",
              "memory_ranges", "thread_count", "dump_timestamp_utc", "error"]
    destination = Path(args.csv).resolve()
    if any(path.resolve() == destination for path in files):
        ap.error("Output must not overwrite input")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8-sig") as output:
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for path in files:
            try:
                with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
                    result = MiniDump(data).inventory()
                result["file"] = str(path)
            except (OSError, ValueError, struct.error) as exc:
                result = {"file": str(path), "error": str(exc)}
            writer.writerow(result)
            print(json.dumps({key: result.get(key) for key in ("file","pid","process_role","signal_version","error")}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
