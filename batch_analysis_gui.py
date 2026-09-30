"""Analysis-only recursive messenger parser GUI.

Run: python code/batch_analysis_gui.py
The --worker mode is internal and also useful for headless verification.
No collector or legacy GUI is imported.
"""
import argparse
import csv
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

DEFAULT_EXTENSIONS = ".raw,.dmp,.dump,.mem,.vmem,.sys,.bin,.img,.dd"
PARSERS = ("Signal", "WhatsApp", "Telegram", "Viber")
SUMMARY_FIELDS = ["source_file", "parser", "status", "records", "seconds", "output_file", "error"]
VIBER_FIELDS = ["offset", "size", "hex", "text", "text_offset", "decode_errors"]


def inside(path, parent):
    return path == parent or parent in path.parents


def extensions_from_text(text):
    result = set()
    for part in text.replace(";", ",").split(","):
        part = part.strip().lower()
        if not part:
            continue
        if part.startswith("*."):
            part = part[1:]
        if not part.startswith("."):
            part = "." + part
        if any(c in part for c in "/\\*? "):
            raise ValueError("Enter extensions separated by commas, such as .raw,.dmp.")
        result.add(part)
    if not result:
        raise ValueError("Enter an extension or select 'All files'.")
    return sorted(result)


def create_run(input_dir, output_dir, parser, extensions, max_search=1000, max_block_bytes=65536,
               include_partial=False, process_only=False, signal_main_pid=None):
    source, output = Path(input_dir).resolve(), Path(output_dir).resolve()
    if not source.is_dir():
        raise ValueError("The input folder does not exist.")
    if source == output:
        raise ValueError("Select an output folder different from the input folder.")
    if parser not in PARSERS:
        raise ValueError("Unsupported parser.")
    if max_search < 12 or max_block_bytes < 120:
        raise ValueError("The search range is too small.")
    output.mkdir(parents=True, exist_ok=True)
    run = output / (datetime.now().strftime("analysis_%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:8])
    run.mkdir()
    config = {
        "input_dir": str(source), "output_dir": str(output), "run_dir": str(run),
        "parser": parser, "extensions": extensions, "max_search": max_search,
        "max_block_bytes": max_block_bytes, "include_partial": bool(include_partial),
        "process_only": bool(process_only),
        "signal_main_pid": int(signal_main_pid) if signal_main_pid is not None else None,
        "created_at": datetime.now().isoformat(),
        "state": "created",
    }
    (run / "run.json").write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    return run / "run.json"


def discover_files(config):
    source = Path(config["input_dir"]).resolve()
    output = Path(config["output_dir"]).resolve()
    excluded = output if inside(output, source) else Path(config["run_dir"]).resolve()
    extensions = set(config["extensions"]) if config["extensions"] is not None else None
    def walk_error(error):
        raise error
    discovered = []
    for directory, folders, names in os.walk(source, followlinks=False, onerror=walk_error):
        current = Path(directory)
        folders[:] = sorted(
            name for name in folders
            if not (current / name).is_symlink()
            and not getattr(os.path, "isjunction", lambda _: False)(current / name)
            and not inside((current / name).resolve(), excluded)
        )
        for name in sorted(names):
            path = current / name
            if path.is_symlink() or not path.is_file():
                continue
            if inside(path.resolve(), excluded):
                continue
            suffix = path.suffix.lower()
            if config.get("process_only") and suffix != ".dmp":
                continue
            signal_pid = config.get("signal_main_pid")
            if config.get("parser") == "Signal" and signal_pid is not None and suffix == ".dmp":
                match = re.search(r"_(\d+)\.dmp$", path.name, re.IGNORECASE)
                if match is None or int(match.group(1)) != int(signal_pid):
                    continue
            if extensions is None or suffix in extensions:
                discovered.append(path)
    yield from sorted(
        discovered,
        key=lambda path: (path.suffix.lower() != ".dmp", str(path).casefold()),
    )


def parser_records(name, data, config, source=None):
    if name == "Signal":
        from parsers.signal_parser import MessageParser, FIELDS
        return FIELDS, MessageParser(data, config["max_search"]).iter_messages(
            include_fragments=config.get("include_partial", False))
    if name == "Viber":
        from parsers.viber_parser import iter_viber_messages
        return VIBER_FIELDS, iter_viber_messages(data, config["max_block_bytes"])
    if name == "WhatsApp":
        from parsers.whatsapp_structure_parser import FIELDS, iter_records

        def records():
            for record in iter_records(
                    data, str(source or "unknown"), config["max_block_bytes"],
                    include_fragments=config.get("include_partial", False)):
                record = dict(record)
                record.pop("source_file", None)
                yield record

        return [field for field in FIELDS if field != "source_file"], records()
    if name == "Telegram":
        from parsers.telegram_structure_parser import FIELDS, iter_records

        def records():
            for record in iter_records(
                    data, str(source or "unknown"), config["max_block_bytes"]):
                record = dict(record)
                record.pop("source_file", None)
                yield record

        return [field for field in FIELDS if field != "source_file"], records()
    raise ValueError("Unknown parser")


def emit(event, **values):
    print(json.dumps({"event": event, **values}, ensure_ascii=True), flush=True)


def analyze_one(source, config):
    from parsers.parser_io import mapped_input, check_output
    relative = source.relative_to(Path(config["input_dir"]))
    destination = Path(config["run_dir"]) / "results" / relative.parent / (
        relative.name + "." + config["parser"].lower() + ".csv")
    check_output(source, destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".part")
    count = 0
    last_update = time.monotonic()
    try:
        with mapped_input(source) as data:
            fields, records = parser_records(config["parser"], data, config, source)
            with temporary.open("x", newline="", encoding="utf-8-sig") as stream:
                writer = csv.DictWriter(stream, fieldnames=["source_file", "parser"] + list(fields))
                writer.writeheader()
                for record in records:
                    writer.writerow({"source_file": str(relative), "parser": config["parser"], **record})
                    count += 1
                    now = time.monotonic()
                    if now - last_update >= 0.5:
                        emit("records", source_file=str(relative), records=count)
                        last_update = now
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return count, str(destination)


def worker_main(config_path):
    config_path = Path(config_path).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["state"] = "running"
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    jobs = []
    try:
        for source in discover_files(config):
            jobs.append(source)
            emit("discovered", source_file=str(source.relative_to(Path(config["input_dir"]))),
                 bytes=source.stat().st_size)
        emit("plan", total=len(jobs))
        failed = 0
        completed_outputs = []
        with (Path(config["run_dir"]) / "summary.csv").open("w", newline="", encoding="utf-8-sig") as stream:
            writer = csv.DictWriter(stream, fieldnames=SUMMARY_FIELDS)
            writer.writeheader()
            for index, source in enumerate(jobs):
                relative = str(source.relative_to(Path(config["input_dir"])))
                emit("started", source_file=relative, index=index, total=len(jobs))
                start = time.monotonic()
                result = dict(source_file=relative, parser=config["parser"], status="completed",
                              records=0, seconds=0, output_file="", error="")
                try:
                    result["records"], result["output_file"] = analyze_one(source, config)
                    completed_outputs.append(result["output_file"])
                except Exception as exc:
                    failed += 1
                    result.update(status="error", error=f"{type(exc).__name__}: {exc}"[:2000])
                result["seconds"] = round(time.monotonic() - start, 3)
                writer.writerow(result)
                stream.flush()
                emit("result", **result)
        if config["parser"] == "Signal":
            from parsers.signal_dedup import merge_results
            config["deduplication"] = merge_results(
                completed_outputs, Path(config["run_dir"]) / "messages_unique.csv")
        elif config["parser"] == "WhatsApp":
            from parsers.whatsapp_structure_parser import merge_result_csvs
            config["deduplication"] = merge_result_csvs(
                completed_outputs, Path(config["run_dir"]) / "messages_unique.csv")
        elif config["parser"] == "Telegram":
            from parsers.telegram_structure_parser import merge_result_csvs
            config["deduplication"] = merge_result_csvs(
                completed_outputs, Path(config["run_dir"]) / "messages_unique.csv")
        config.update(state="completed_with_errors" if failed else "completed",
                      total=len(jobs), failed=failed, finished_at=datetime.now().isoformat())
        config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
        emit("done", total=len(jobs), failed=failed, deduplication=config.get("deduplication"))
        return 0
    except Exception as exc:
        config.update(state="failed", error=f"{type(exc).__name__}: {exc}"[:2000],
                      finished_at=datetime.now().isoformat())
        config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
        emit("fatal", error=config["error"])
        return 1


def launch_gui():
    from PyQt5.QtCore import QProcess, QProcessEnvironment, QTimer, QUrl, Qt
    from PyQt5.QtGui import QDesktopServices
    from PyQt5.QtWidgets import (
        QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel,
        QLineEdit, QPushButton, QFileDialog, QComboBox, QCheckBox, QSpinBox,
        QGroupBox, QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
        QPlainTextEdit, QMessageBox, QAbstractItemView,
    )

    class AnalysisWindow(QWidget):
        def __init__(self):
            super().__init__()
            self.process = None
            self.config_path = None
            self.jobs = {}
            self.buffer = bytearray()
            self.cancelled = False
            self.close_after_stop = False
            self.worker_done = False
            self.fatal_error = ""
            self.setWindowTitle("Batch Messenger Memory Analysis")
            self.resize(1080, 760)
            layout = QVBoxLayout(self)
            title = QLabel("Batch Memory File Analysis")
            title.setStyleSheet("font-size: 22px; font-weight: 600;")
            layout.addWidget(title)
            layout.addWidget(QLabel("Select folders and a parser to analyze files recursively and save one CSV per file."))
            self.options = QGroupBox("Analysis Settings")
            form = QFormLayout(self.options)
            self.input_edit, self.output_edit = QLineEdit(), QLineEdit()
            for label, edit, callback in [
                ("Input folder", self.input_edit, self.choose_input),
                ("Output folder", self.output_edit, self.choose_output),
            ]:
                row = QHBoxLayout()
                row.addWidget(edit)
                button = QPushButton("Browse")
                button.clicked.connect(callback)
                row.addWidget(button)
                form.addRow(label, row)
            self.parser_combo = QComboBox()
            self.parser_combo.addItems(PARSERS)
            form.addRow("Parser", self.parser_combo)
            self.extensions_edit = QLineEdit(DEFAULT_EXTENSIONS)
            self.all_files = QCheckBox("All files, regardless of extension")
            self.all_files.toggled.connect(lambda checked: self.extensions_edit.setEnabled(not checked))
            self.process_only = QCheckBox("Fast analysis: process dumps (.dmp) only")
            row = QHBoxLayout()
            row.addWidget(self.extensions_edit)
            row.addWidget(self.all_files)
            form.addRow("File extensions", row)
            form.addRow("", self.process_only)
            self.max_search, self.max_block = QSpinBox(), QSpinBox()
            self.max_search.setRange(12, 16777216)
            self.max_search.setValue(1000)
            self.max_search.setSuffix(" bytes")
            self.max_block.setRange(120, 16777216)
            self.max_block.setValue(65536)
            self.max_block.setSuffix(" bytes")
            form.addRow("Signal search range", self.max_search)
            self.signal_pid = QSpinBox()
            self.signal_pid.setRange(0, 429496729)
            self.signal_pid.setSpecialValueText("Any PID")
            self.signal_pid.setValue(0)
            self.signal_pid.setToolTip("Optionally analyze only Signal process dumps whose final filename PID matches this value.")
            form.addRow("Signal main PID", self.signal_pid)
            form.addRow("Viber / WhatsApp / Telegram structure limit", self.max_block)
            self.include_partial = QCheckBox("Include partial structures (evidence mode)")
            self.include_partial.setChecked(False)
            form.addRow("Result scope", self.include_partial)
            self.parser_combo.currentTextChanged.connect(self.sync_parser_options)
            self.sync_parser_options()
            layout.addWidget(self.options)
            note = QLabel("Each run creates a new output folder. File names and subfolders are preserved, and a CSV is created even when no records are found.")
            note.setWordWrap(True)
            layout.addWidget(note)
            buttons = QHBoxLayout()
            self.start_button = QPushButton("Start analysis")
            self.start_button.clicked.connect(self.start_analysis)
            self.cancel_button = QPushButton("Cancel")
            self.cancel_button.setEnabled(False)
            self.cancel_button.clicked.connect(self.cancel_analysis)
            self.open_button = QPushButton("Open output folder")
            self.open_button.setEnabled(False)
            self.open_button.clicked.connect(self.open_results)
            buttons.addWidget(self.start_button)
            buttons.addWidget(self.cancel_button)
            buttons.addStretch()
            buttons.addWidget(self.open_button)
            layout.addLayout(buttons)
            self.progress = QProgressBar()
            self.progress.setRange(0, 100)
            self.progress.setValue(0)
            layout.addWidget(self.progress)
            self.status = QLabel("Ready")
            self.status.setWordWrap(True)
            layout.addWidget(self.status)
            self.table = QTableWidget(0, 5)
            self.table.setHorizontalHeaderLabels(["Input file (relative path)", "Size", "Status", "Messages", "Elapsed time"])
            self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
            for col in range(1, 5):
                self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
            layout.addWidget(self.table, 1)
            self.log = QPlainTextEdit()
            self.log.setReadOnly(True)
            self.log.setMaximumBlockCount(2000)
            self.log.setMaximumHeight(150)
            layout.addWidget(self.log)

        def sync_parser_options(self):
            signal = self.parser_combo.currentText() == "Signal"
            self.max_search.setEnabled(signal)
            self.signal_pid.setEnabled(signal)
            self.max_block.setEnabled(not signal)
            self.include_partial.setEnabled(
                self.parser_combo.currentText() in ("Signal", "WhatsApp")
            )

        def choose_input(self):
            path = QFileDialog.getExistingDirectory(self, "Select input folder", self.input_edit.text())
            if path:
                self.input_edit.setText(path)
                if not self.output_edit.text().strip():
                    source = Path(path)
                    self.output_edit.setText(str(source.parent / (source.name + "_analysis")))

        def choose_output(self):
            path = QFileDialog.getExistingDirectory(self, "Select output folder", self.output_edit.text())
            if path:
                self.output_edit.setText(path)

        def start_analysis(self):
            if self.process is not None:
                return
            try:
                if not self.input_edit.text().strip() or not self.output_edit.text().strip():
                    raise ValueError("Select input and output folders.")
                extensions = None if self.all_files.isChecked() else extensions_from_text(self.extensions_edit.text())
                parser_name = self.parser_combo.currentText()
                config_path = create_run(
                    self.input_edit.text().strip(), self.output_edit.text().strip(),
                    parser_name, extensions,
                    self.max_search.value(), self.max_block.value(),
                    self.include_partial.isChecked(), self.process_only.isChecked(),
                    self.signal_pid.value() if parser_name == "Signal" and self.signal_pid.value() else None)
            except (OSError, ValueError) as exc:
                QMessageBox.warning(self, "Check settings", str(exc))
                return
            self.config_path = config_path
            self.config = json.loads(config_path.read_text(encoding="utf-8"))
            self.jobs.clear()
            self.table.setRowCount(0)
            self.log.clear()
            self.buffer.clear()
            self.cancelled = self.worker_done = False
            self.fatal_error = ""
            self.options.setEnabled(False)
            self.start_button.setEnabled(False)
            self.cancel_button.setEnabled(True)
            self.open_button.setEnabled(True)
            self.progress.setRange(0, 0)
            self.status.setText("Finding files to analyze in subfolders...")
            self.log.appendPlainText(f"Output: {config_path.parent}")
            process = QProcess(self)
            self.process = process
            environment = QProcessEnvironment.systemEnvironment()
            environment.insert("PYTHONIOENCODING", "utf-8")
            process.setProcessEnvironment(environment)
            process.setProgram(sys.executable)
            process.setArguments(["-u", str(Path(__file__).resolve()), "--worker", str(config_path)])
            process.readyReadStandardOutput.connect(self.read_output)
            process.readyReadStandardError.connect(self.read_errors)
            process.finished.connect(self.process_finished)
            process.errorOccurred.connect(self.process_error)
            process.start()

        def read_output(self):
            if self.process is None:
                return
            self.buffer.extend(bytes(self.process.readAllStandardOutput()))
            while b"\n" in self.buffer:
                line, _, rest = self.buffer.partition(b"\n")
                self.buffer = bytearray(rest)
                try:
                    self.handle_event(json.loads(line))
                except (ValueError, KeyError, TypeError) as exc:
                    self.log.appendPlainText(f"Could not read worker status: {exc}")

        def read_errors(self):
            if self.process is not None:
                text = bytes(self.process.readAllStandardError()).decode("utf-8", errors="replace")
                if text.strip():
                    self.log.appendPlainText(text.strip())

        def handle_event(self, event):
            kind = event["event"]
            if kind == "discovered":
                source = event["source_file"]
                row = self.table.rowCount()
                self.table.insertRow(row)
                self.jobs[source] = {"row": row, "source_file": source, "parser": self.config["parser"],
                                     "status": "pending", "records": 0, "seconds": "",
                                     "output_file": "", "error": ""}
                for col, value in enumerate([source, f'{event["bytes"]/1024**2:,.1f} MiB', "Pending", "", ""]):
                    self.table.setItem(row, col, QTableWidgetItem(str(value)))
                self.status.setText(f"Finding files: {len(self.jobs):,} files")
            elif kind == "plan":
                self.progress.setRange(0, max(1, event["total"]))
                self.progress.setValue(0)
                self.status.setText(f'Files to analyze: {event["total"]:,} files')
            elif kind in ("started", "records", "result"):
                source = event["source_file"]
                job = self.jobs[source]
                row = job["row"]
                if kind == "started":
                    job["status"] = "running"
                    self.table.item(row, 2).setText("Analyzing")
                    self.status.setText(f'{event["index"]+1}/{event["total"]} · {source}')
                    self.table.scrollToItem(self.table.item(row, 0))
                elif kind == "records":
                    job["records"] = event["records"]
                    self.table.item(row, 3).setText(f'{event["records"]:,}')
                else:
                    job.update({key: event[key] for key in SUMMARY_FIELDS})
                    label = "Completed" if job["status"] == "completed" else "Error"
                    self.table.item(row, 2).setText(label)
                    self.table.item(row, 3).setText(f'{job["records"]:,}' if label == "Completed" else "")
                    self.table.item(row, 4).setText(f'{job["seconds"]:.2f} s')
                    self.progress.setValue(sum(j["status"] in ("completed", "error") for j in self.jobs.values()))
                    self.log.appendPlainText(
                        f'{label} · {source} · {job["records"]:,} records' if label == "Completed"
                        else f'Error · {source} · {job["error"]}')
            elif kind == "done":
                self.worker_done = True
                if event.get("deduplication") is not None:
                    self.config["deduplication"] = event["deduplication"]
                    self.log.appendPlainText("Deduplicated CSV: " + event["deduplication"]["output_file"])
            elif kind == "fatal":
                self.fatal_error = event["error"]
                self.log.appendPlainText("Analysis error: " + self.fatal_error)

        def cancel_analysis(self):
            if self.process is None:
                return
            self.cancelled = True
            self.cancel_button.setEnabled(False)
            self.status.setText("Cancelling analysis... Completed CSV files will be retained.")
            self.process.kill()

        def process_error(self, error):
            if error == QProcess.FailedToStart:
                self.fatal_error = "Could not start the analysis process."
                self.process_finished(-1, QProcess.CrashExit)

        def process_finished(self, exit_code, exit_status):
            if self.process is None:
                return
            self.read_output()
            self.read_errors()
            process, self.process = self.process, None
            process.deleteLater()
            if self.cancelled:
                state = "cancelled"
            elif not self.worker_done or exit_code != 0:
                state = "failed"
            else:
                state = "completed_with_errors" if any(j["status"] == "error" for j in self.jobs.values()) else "completed"
            # A worker killed while writing leaves only .part files, never a final CSV.
            for job in self.jobs.values():
                if job["status"] in ("running", "pending"):
                    job["status"] = "cancelled" if self.cancelled else "not_run"
                    job["records"] = 0
                    self.table.item(job["row"], 2).setText("Cancel" if self.cancelled else "Not run")
                    self.table.item(job["row"], 3).setText("")
            try:
                run = self.config_path.parent.resolve()
                for partial in (run / "results").rglob("*.csv.part"):
                    if inside(partial.resolve(), run):
                        partial.unlink()
                with (run / "summary.csv").open("w", newline="", encoding="utf-8-sig") as stream:
                    writer = csv.DictWriter(stream, fieldnames=SUMMARY_FIELDS, extrasaction="ignore")
                    writer.writeheader()
                    writer.writerows(self.jobs.values())
                self.config.update(state=state, finished_at=datetime.now().isoformat(), exit_code=exit_code)
                self.config_path.write_text(json.dumps(self.config, ensure_ascii=False, indent=2), encoding="utf-8")
            except OSError as exc:
                self.log.appendPlainText(f"Could not save the run log: {exc}")
            complete = sum(j["status"] == "completed" for j in self.jobs.values())
            errors = sum(j["status"] == "error" for j in self.jobs.values())
            count = sum(j["records"] for j in self.jobs.values() if j["status"] == "completed")
            label = {"cancelled": "Cancelled", "failed": "Failed", "completed": "Analysis completed",
                     "completed_with_errors": "Analysis completed with errors"}[state]
            count_label = "Total file records"
            if self.worker_done and self.config.get("deduplication") is not None:
                count = self.config["deduplication"]["unique_messages"]
                count_label = "Unique messages"
            self.status.setText(
                f"{label} · {complete:,} completed / {errors:,} failed / "
                f"{count_label}: {count:,}"
            )
            if not self.jobs and state == "completed":
                self.status.setText("No matching files found. Check the input folder and extensions.")
            self.progress.setRange(0, max(1, len(self.jobs)))
            self.progress.setValue(complete + errors)
            self.options.setEnabled(True)
            self.sync_parser_options()
            self.start_button.setEnabled(True)
            self.cancel_button.setEnabled(False)
            if self.close_after_stop:
                self.close()

        def open_results(self):
            if self.config_path:
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.config_path.parent)))

        def closeEvent(self, event):
            if self.process is not None:
                self.close_after_stop = True
                self.cancel_analysis()
                event.ignore()
            else:
                event.accept()

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = AnalysisWindow()
    window.show()
    return app.exec_()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worker", metavar="CONFIG_JSON", help=argparse.SUPPRESS)
    args = ap.parse_args()
    return worker_main(args.worker) if args.worker else launch_gui()


if __name__ == "__main__":
    raise SystemExit(main())
